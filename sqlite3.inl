static const char *EMKY = "\0LASTERRORMESSAGE"; // 17 bytes
#define EMKYLEN 17

static void set_last_error(const char *msg,const char *post) {
	keyvalue kv;
	int lm,lp;

	pthread_rwlock_wrlock(&kvs_lock);
	HASH_FIND(hh,kvs,EMKY,EMKYLEN,kv);

	if (kv) {
		HASH_DELETE(hh,kvs,kv);
		free(kv->kv_key);
		free(kv->kv_val);
		free(kv);
	}

	kv = malloc(sizeof(struct _keyvalue));
	kv->kv_key = malloc(EMKYLEN);
	memcpy(kv->kv_key,EMKY,EMKYLEN);

	if (post != NULL) {
		lm = strlen(msg);
		lp = strlen(post);
		kv->kv_val = malloc(lm + lp + 1);
		memcpy(kv->kv_val,msg,lm);
		memcpy(&kv->kv_val[lm],post,lp);
		kv->kv_val[lm + lp] = '\0';
	} else {
		kv->kv_val = strdup(msg);
	}
	kv->kv_tmr = NULL;

	HASH_ADD_KEYPTR(hh,kvs,EMKY,EMKYLEN,kv);
	pthread_rwlock_unlock(&kvs_lock);

}

static int ph7_get_last_error(ph7_context *ctx, int argc, ph7_value **argv) {
	keyvalue kv;

	pthread_rwlock_rdlock(&kvs_lock);
	HASH_FIND(hh,kvs,EMKY,EMKYLEN,kv);
	pthread_rwlock_unlock(&kvs_lock);

	if (kv) {
		ph7_result_string(ctx,kv->kv_val,strlen(kv->kv_val));
	} else {
		fprintf(stderr,"get_last_error: could not find key in kvs\n");
		ph7_result_null(ctx);
	}

	return PH7_OK;
}

static int ph7_sqlite_open(ph7_context *ctx, int argc, ph7_value **argv) {
	sqlite3 *db = NULL;
	const char *name;
	char *value;
	int len,rc = PH7_OK;
	keyvalue new,old;

	if (argc < 1) {
		set_last_error("Missing argument",NULL);
		goto DONE;
	}

	if (!ph7_value_is_string(argv[0])) {
		set_last_error("Invalid argument: want string",NULL);
		goto DONE;
	}

	name = ph7_value_to_string(argv[0],&len);
	if (len < 1) {
		set_last_error("Invalid argument: string must not be blank",NULL);
		goto DONE;
	}

	if (sqlite3_open(name,&db) != SQLITE_OK) {
		set_last_error("Sqlite3 error:",sqlite3_errmsg(db));
		db = NULL;
	}

DONE:
	ph7_result_int(ctx,(int)db);
	return PH7_OK;
}

static int ph7_sqlite_close(ph7_context *ctx, int argc, ph7_value **argv) {
	sqlite3 *db = NULL;

	if (argc < 1) {
		set_last_error("Missing argument",NULL);
		goto DONE;
	}

	if (!ph7_value_is_int(argv[0])) {
		set_last_error("Invalid argument: not a database handle",NULL);
		goto DONE;
	}

	db = (sqlite3 *)ph7_value_to_int(argv[0]);
	if ((void *)db - (void *)0x8000000 < 1) {
		set_last_error("Invalid argument: not a  database handle",NULL);
		db = NULL;
		goto DONE;
	}

	sqlite3_close(db);
	db = (sqlite3 *)1;

DONE:
	ph7_result_bool(ctx,(int)db);
	return PH7_OK;
}

static int ph7_sqlite_query(ph7_context *ctx, int argc, ph7_value **argv) {
	sqlite3 *db;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	int qlen,rc,done,retry,i,count,row;
	ph7_value *result = NULL,*arr = NULL,*val = NULL;
	char idx[16];

	if (argc < 2) {
		set_last_error("Missing argument(s)",NULL);
		goto FAIL;
	}

	if (!ph7_value_is_int(argv[0]) || !ph7_value_is_string(argv[1])) {
		set_last_error("Invalid argument(s) (want int, string)",NULL);
		goto FAIL;
	}

	db = (sqlite3 *)ph7_value_to_int(argv[0]);
	if (db == NULL || (void *)db - (void *)0x8000000 < 1) {
		set_last_error("Invalid sqlite3 database handle",NULL);
		goto FAIL;
	}

	query = ph7_value_to_string(argv[1],&qlen);
	if (qlen < 7) {
		set_last_error("Invalid sqlite3 query",NULL);
		goto FAIL;
	}

	if (sqlite3_prepare(db,query,qlen,&stmt,NULL) != SQLITE_OK) {
		set_last_error("Sqlite3 error:",sqlite3_errmsg(db));
		goto FAIL;
	}

	done = 0;
	retry = 5;
	row = 1;
	count = 0;
	result = ph7_context_new_array(ctx);
	val = ph7_context_new_scalar(ctx);
	while (!done) {
		switch (sqlite3_step(stmt)) {
			case SQLITE_BUSY:
				if (--retry == 0) {
					set_last_error("Sqlite3 error:",sqlite3_errmsg(db));
				} else {
					usleep(5000);
					continue;
				}
			break;
			case SQLITE_DONE:
				done = 1;
			break;
			case SQLITE_ROW:
				arr = ph7_context_new_array(ctx);
				if (count == 0) {
					count = sqlite3_column_count(stmt);
					if (count == 0) {
						ph7_array_add_intkey_elem(result,0,arr);
						done = 1;
						break;
					}
					for (i = 0; i < count; i++) {
						ph7_value_reset_string_cursor(val);
						ph7_value_string(val,sqlite3_column_name(stmt,i),-1);
						ph7_array_add_intkey_elem(arr,i,val);
					}
					ph7_array_add_intkey_elem(result,0,arr);
					arr = ph7_context_new_array(ctx);
				}
				for (i = 0; i < count; i++) {
					switch (sqlite3_column_type(stmt,i)) {
						case SQLITE_INTEGER:
							ph7_value_int64(val,sqlite3_column_int64(stmt,i));
						break;
						case SQLITE_FLOAT:
							ph7_value_double(val,sqlite3_column_double(stmt,i));
						break;
						case SQLITE_TEXT:
							ph7_value_string(val,sqlite3_column_text(stmt,i),-1);
						break;
						default: // note: blobs are not handled
							ph7_value_null(val);
					}
					ph7_array_add_intkey_elem(arr,i,val);
				}
				ph7_array_add_intkey_elem(result,row++,arr);
			break;
			default:
				set_last_error("Sqlite3 error:",sqlite3_errmsg(db));
		}
	}

	sqlite3_finalize(stmt);
	ph7_result_value(ctx,result);
	return PH7_OK;

FAIL:
	if (stmt != NULL) sqlite3_finalize(stmt);
	return PH7_OK;
}

