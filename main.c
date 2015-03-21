#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include "config.h"
#include "civetweb.h"
#include "ph7.h"
#include "uthash.h"
#include "main.h"
#ifdef USE_SQLITE
#include <sqlite3.h>
#endif

static int DONE = 0;
static const char * options[] = {
	"document_root", ROOT,
	"listening_ports", PORT,
	"num_threads", NTHR,
	NULL
};
static struct mg_callbacks callbacks;
static struct mg_context *ctx;
static keyvalue kvs = NULL;
static pthread_rwlock_t kvs_lock;
#ifdef SCRIPT_CACHE
static script_data scripts = NULL;
static pthread_rwlock_t script_lock;
#endif

static void sig_handler(int sig) {
	DONE = 1;
}

static void timer_handler(int sig,siginfo_t *si,void *uc) {
	char *key = si->si_value.sival_ptr;
	keyvalue kv;

	pthread_rwlock_rdlock(&kvs_lock);
	HASH_FIND(hh,kvs,key,strlen(key),kv);
	pthread_rwlock_unlock(&kvs_lock);

	if (kv) {
		pthread_rwlock_wrlock(&kvs_lock);
		HASH_DEL(kvs,kv);
		pthread_rwlock_unlock(&kvs_lock);
		free(kv->kv_key);
		if (kv->kv_val) free(kv->kv_val);
		timer_delete(kv->kv_tmr);
		free(kv);
	}
}

// bool kv_put(string key, string value, int expiry);
static int ph7_kv_put(ph7_context *ctx,int argc, ph7_value **argv) {
	keyvalue new = NULL,old = NULL;
	const char *key,*value;
	int klen,vlen,secs,rc = PH7_OK;
	struct sigevent sev = {0};
	struct itimerspec its = {0};

	if (argc < 3) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Missing argument(s)");
		goto FAIL;
	}
	
	if (!(ph7_value_is_string(argv[0]) && ph7_value_is_string(argv[1]))) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Argument(s) incorrect (key and value must be strings)");
		return PH7_OK;
	}

	key = ph7_value_to_string(argv[0],&klen);
	value = ph7_value_to_string(argv[1],&vlen);
	secs = ph7_value_to_int(argv[2]);
	
	if (!key || !*key) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Invalid key argument, must not be blank");
		goto FAIL;
	}

	pthread_rwlock_rdlock(&kvs_lock);
	HASH_FIND(hh,kvs,key,klen,old);
	pthread_rwlock_unlock(&kvs_lock);

	if ((new = malloc(sizeof(_keyvalue))) == NULL) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Out of memory");
		rc = PH7_ABORT;
		goto FAIL;
	}

	if (old) {
		if (old->kv_tmr) {
			if (secs < 1) { timer_delete(old->kv_tmr); old->kv_tmr = NULL; }
			else {
				its.it_value.tv_sec = secs;
				timer_settime(old->kv_tmr,0,&its,NULL);
			}
		}
		new->kv_key = old->kv_key;
		new->kv_val = old->kv_val;
		new->kv_tmr = old->kv_tmr;
		pthread_rwlock_wrlock(&kvs_lock);
		HASH_DEL(kvs,old);
		pthread_rwlock_unlock(&kvs_lock);
		free(old);
	} else {
		new->kv_key = strdup(key);
		new->kv_val = strdup(value);
		new->kv_tmr = NULL;

		if (secs > 0) {
			sev.sigev_notify = SIGEV_SIGNAL;
			sev.sigev_signo = SIGRTMAX - 1;
			sev.sigev_value.sival_ptr = new->kv_key;
			if (timer_create(CLOCK_REALTIME,&sev,&new->kv_tmr) == -1) {
				ph7_context_throw_error(ctx,PH7_CTX_ERR,"Could not create timer");
				rc = PH7_ABORT;
				goto FAIL;
			}
			its.it_value.tv_sec = secs;
			if (timer_settime(new->kv_tmr,0,&its,NULL) == -1) {
				ph7_context_throw_error(ctx,PH7_CTX_ERR,"Could not set timer");
				rc =  PH7_ABORT;
				goto FAIL;
			}
		}
	}
	
	pthread_rwlock_wrlock(&kvs_lock);
	HASH_ADD_KEYPTR(hh,kvs,new->kv_key,klen,new);
	pthread_rwlock_unlock(&kvs_lock);

	ph7_result_bool(ctx,1);
	return PH7_OK;

FAIL:
	if (new) {
		if (new->kv_key) free(new->kv_key);
		if (new->kv_val) free(new->kv_val);
		free(new);
	}
	if (rc == PH7_OK) ph7_result_bool(ctx,0);
	return rc;
}

// string kv_put_nx(string key, string value, expiry)
static int ph7_kv_put_nx(ph7_context *ctx,int argc, ph7_value **argv) {
	keyvalue new = NULL,old = NULL;
	const char *key,*value;
	int klen,vlen,secs,rc = PH7_OK;
	struct sigevent sev = {0};
	struct itimerspec its = {0};

	if (argc < 3) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Missing argument(s)");
		goto FAIL;
	}
	
	if (!(ph7_value_is_string(argv[0]) && ph7_value_is_string(argv[1]))) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Argument(s) incorrect (key and value must be strings)");
		return PH7_OK;
	}

	key = ph7_value_to_string(argv[0],&klen);
	value = ph7_value_to_string(argv[1],&vlen);
	secs = ph7_value_to_int(argv[2]);
	
	if (!key || !*key) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Invalid key argument, must not be blank");
		goto FAIL;
	}

	pthread_rwlock_rdlock(&kvs_lock);
	HASH_FIND(hh,kvs,key,klen,old);
	pthread_rwlock_unlock(&kvs_lock);

	if (old) {
		ph7_result_bool(ctx,0);
		return PH7_OK;
	} else {
		if ((new = malloc(sizeof(_keyvalue))) == NULL) {
			ph7_context_throw_error(ctx,PH7_CTX_ERR,"Out of memory");
			rc = PH7_ABORT;
			goto FAIL;
		}
		new->kv_key = strdup(key);
		new->kv_val = strdup(value);
		
		if (secs < 1) {
			new->kv_tmr = NULL;
		} else {
			sev.sigev_notify = SIGEV_SIGNAL;
			sev.sigev_signo = SIGRTMAX - 1;
			sev.sigev_value.sival_ptr = new->kv_key;
			if (timer_create(CLOCK_REALTIME,&sev,&new->kv_tmr) == -1) {
				ph7_context_throw_error(ctx,PH7_CTX_ERR,"Could not create timer");
				rc = PH7_ABORT;
				goto FAIL;
			}
			its.it_value.tv_sec = secs;
			if (timer_settime(new->kv_tmr,0,&its,NULL) == -1) {
				ph7_context_throw_error(ctx,PH7_CTX_ERR,"Could not set timer");
				rc =  PH7_ABORT;
				goto FAIL;
			}
		}
	}
	
	pthread_rwlock_wrlock(&kvs_lock);
	HASH_ADD_KEYPTR(hh,kvs,new->kv_key,klen,new);
	pthread_rwlock_unlock(&kvs_lock);

	ph7_result_bool(ctx,1);

FAIL:
	if (new) {
		if (new->kv_key) free(new->kv_key);
		if (new->kv_val) free(new->kv_val);
		if (new->kv_tmr) timer_delete(new->kv_tmr);
		free(new);
	}
	if (rc == PH7_OK) ph7_result_null(ctx);
	return rc;
}

// string kv_get(string key)
static int ph7_kv_get(ph7_context *ctx,int argc,ph7_value **argv) {
	const char *key;
	int klen;
	keyvalue kv;

	if (argc < 1) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Missing parameter");
		ph7_result_null(ctx);
		return PH7_OK;
	}

	key = ph7_value_to_string(argv[0],&klen);

	if (!*key) {
		ph7_context_throw_error(ctx,PH7_CTX_ERR,"Invalid key argument, must not be blank, must be castable to string");
		ph7_result_null(ctx);
		return PH7_OK;
	}

	pthread_rwlock_rdlock(&kvs_lock);
	HASH_FIND(hh,kvs,key,klen,kv);
	pthread_rwlock_unlock(&kvs_lock);

	if (kv) ph7_result_string(ctx,kv->kv_val,-1);
	else ph7_result_null(ctx);
	
	return PH7_OK;
}

#ifdef USE_SQLITE
#include "sqlite3.inl"
#endif

static void do500(struct mg_connection *conn,char *msg) {
	size_t msglen = 0;
	mg_write(conn,HEADER500,sizeof(HEADER500));
	if (msg && *msg) msglen = strlen(msg);
	mg_printf(conn,"Content-Length:%d\r\n\r\n",msglen);
	if (msglen) mg_write(conn,msg,msglen);
}

static void do404(struct mg_connection *conn,char *msg) {
	size_t msglen = 0;
	mg_write(conn,HEADER500,sizeof(HEADER500));
	if (msg && *msg) msglen = strlen(msg);
	mg_printf(conn,"Content-Length:%d\r\n\r\n",msglen + 16);
	mg_write(conn,"file not found: ",16);
	if (msglen) mg_write(conn,msg,msglen);
}

static int output_callback(const void* output,unsigned int length,void *cbdata) {
	struct mg_connection *conn = cbdata;
	mg_write(conn,output,length);
	return PH7_OK;
}

static int php_handler(struct mg_connection *conn, void *cbdata) {
	struct mg_request_info req = conn->request_info;
	ph7 *engine = cbdata;
	ph7_vm *php = NULL;
	const char *errlog = NULL;
	const char *uri;
	char *buff = NULL;
	int c = 0,i,odd = 1;

	uri = req.uri;
	// force URI relative to document_root
	if (*uri == '/') uri = &uri[1];
#ifdef SCRIPT_CACHE
	script_data script;
	int nlen = strlen(uri);


	pthread_rwlock_rdlock(&script_lock);
	HASH_FIND(hh,scripts,uri,nlen,script);
	pthread_rwlock_unlock(&script_lock);

if (!script) {
	script = malloc(sizeof(struct _script_data));
	script->key = strdup(uri);
#endif
	// attempt to compile the script
	if (ph7_compile_file(engine,uri,&php,0) != PH7_OK) goto FAIL;
#ifdef SCRIPT_CACHE
	script->engine = php;
	pthread_rwlock_wrlock(&script_lock);
	HASH_ADD_KEYPTR(hh,scripts,script->key,nlen,script);
	pthread_rwlock_unlock(&script_lock);
} else {
	php = script->engine;
	ph7_vm_reset(php);
}
#endif

	// set an include path to add to the search directories
	if (ph7_vm_config(php,PH7_VM_CONFIG_IMPORT_PATH,HOME "/ph7_include") != PH7_OK) goto FAIL;
	/* set $_HEADERS
	for (i = 0; i < req.num_headers; i++) {
		if (ph7_vm_config(php,PH7_VM_CONFIG_HEADER_ATTR,req.http_headers[i].name,req.http_headers[i].value,-1) != PH7_OK) goto FAIL;
	}*/

	/*
	 * civetweb modifies the request it recieves, dicing it into nice individual strings.
	 * unfortunately, I need access to something resembling the original request.
	 */
	buff = malloc(conn->data_len);
	memcpy(buff,conn->buf,conn->data_len);
	for (i = 0; i < conn->data_len - 1; i++) {
		if (buff[i] == '\0') {
			if (buff[i+1] == '\0') {
				if (odd) {
					buff[i] = '\r';
					buff[i+1] = '\n';
					if (buff[i + 2] == '\0') {
						buff[i+2] = '\r';
						buff[i+3] = '\n';
						i += 2;
					}
				}
				else {
					buff[i] = ':';
					buff[i+1] = ' ';
				}
				i += 2;
				odd = odd ? 0 : 1;
			} else {
				if (c == 1 && buff[i+1] != 'H') buff[i] = '?';
				else buff[i] = ' ';
				c++;
			}
		}
	}

	// try to parse the request buffer with PH7
	if (ph7_vm_config(php,PH7_VM_CONFIG_HTTP_REQUEST,buff,conn->data_len) != PH7_OK) goto FAIL;
	// add our key-value store functions
	if (ph7_create_function(php,"kv_put",ph7_kv_put,NULL) != PH7_OK) goto FAIL;
	if (ph7_create_function(php,"kv_put_nx",ph7_kv_put_nx,NULL) != PH7_OK) goto FAIL;
	if (ph7_create_function(php,"kv_get",ph7_kv_get,NULL) != PH7_OK) goto FAIL;
	// add the sqlite functions, if requested
#ifdef USE_SQLITE
	if (ph7_create_function(php,"sqlite_open",ph7_sqlite_open,NULL) != PH7_OK) goto FAIL;
	if (ph7_create_function(php,"sqlite_close",ph7_sqlite_close,NULL) != PH7_OK) goto FAIL;
	if (ph7_create_function(php,"sqlite_query",ph7_sqlite_query,NULL) != PH7_OK) goto FAIL;
	if (ph7_create_function(php,"get_last_error",ph7_get_last_error,NULL) != PH7_OK) goto FAIL;
#endif
	// set the import path
	if (ph7_vm_config(php,PH7_VM_CONFIG_IMPORT_PATH,IMPP) != PH7_OK) goto FAIL;
	// configure error logging
	if (ph7_vm_config(php,PH7_VM_CONFIG_ERR_REPORT) != PH7_OK) goto FAIL;
	// set the output handler
	if (ph7_vm_config(php,PH7_VM_CONFIG_OUTPUT,output_callback,conn) != PH7_OK) goto FAIL;
	
	// execute the compiled script
	ph7_vm_exec(php,NULL);
	goto DONE;
FAIL:
	ph7_config(engine,PH7_CONFIG_ERR_LOG,&errlog,NULL);
	if (*errlog) do500(conn,(char *)errlog);
	else do500(conn,"unknown error");
DONE:
	if (buff) free(buff);
#ifndef SCRIPT_CACHE
	if (php) ph7_vm_release(php);
#endif
	return 1;
}

int main(int argc, char **argv) {
	pid_t pid;
	int fd;
	ph7 *engine;
	struct sigaction sa;
	keyvalue kv,kvt;
#ifdef SCRIPT_CACHE
	script_data sc,st;
	if (pthread_rwlock_init(&script_lock,NULL) != 0) exit(1);
#endif

	if (pthread_rwlock_init(&kvs_lock,NULL) != 0) exit(1);

	// daemonize
  pid = fork();
  if (pid < 0) exit(1);
  if (pid > 0) exit(0);
  if (setsid() < 0) exit(1);
  pid = fork();
  if (pid < 0) exit(1);
  if (pid > 0) exit(0);
  umask(22);
  for (fd = sysconf(_SC_OPEN_MAX); fd > -1; fd--) close(fd);

  chdir(ROOT);
	// install signale handlers for SIGTERM and SIGINT
  if (signal(SIGTERM,sig_handler) == SIG_ERR) exit(1);
  if (signal(SIGINT,sig_handler) == SIG_ERR) exit(1);
	
	// install handler for SIGRTx 
	sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = timer_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGRTMAX - 1,&sa,NULL);

	// initialize ph7 engine
	if (ph7_init(&engine) != PH7_OK) exit(1);

	// start the server proper
	memset(&callbacks,0,sizeof(callbacks));
	if ((ctx = mg_start(&callbacks,NULL,options)) == NULL) exit(1);
	mg_set_request_handler(ctx,"**.php",php_handler,engine);

	// spin until SIGTERM or SIGINT
	while (!DONE) {
		usleep(500);
	}

	// cleanup
	mg_stop(ctx);
	pthread_rwlock_destroy(&kvs_lock);
	HASH_ITER(hh,kvs,kv,kvt) {
		HASH_DEL(kvs,kv);
		free(kv->kv_key);
		if (kv->kv_val != NULL) free(kv->kv_val);
		if (kv->kv_tmr != NULL) timer_delete(kv->kv_tmr);
		free(kv);
	}
#ifdef SCRIPT_CACHE
	HASH_ITER(hh,scripts,sc,st) {
		HASH_DEL(scripts,sc);
		free(sc->key);
		ph7_vm_release(sc->engine);
		free(sc);
	}
	pthread_rwlock_destroy(&script_lock);
#endif
	ph7_release(engine);
	ph7_lib_shutdown();
	exit(0);

}
