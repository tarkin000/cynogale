#define HEADER404 "HTTP/1.1 404 Not Found\r\nContent-Type:text/plain;charset=UTF-8\r\n"
#define HEADER500 "HTTP/1.1 500 Internal Server Error\r\nContent-Type:text/plain;charset=UTF-8\r\n"

#ifdef NO_SSL
#define SSL void
#define SSL_CTX void
#endif

// included some private definitions from civetweb.h here because I need access to some members ;)
typedef int SOCKET;
union usa {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(USE_IPV6)
    struct sockaddr_in6 sin6;
#endif
};

struct socket {
    SOCKET sock;          /* Listening socket */
    union usa lsa;        /* Local socket address */
    union usa rsa;        /* Remote socket address */
    unsigned is_ssl:1;    /* Is port SSL-ed */
    unsigned ssl_redir:1; /* Is port supposed to redirect everything to SSL port */
};

struct mg_connection {
    struct mg_request_info request_info;
    struct mg_context *ctx;
    SSL *ssl;                       /* SSL descriptor */
    SSL_CTX *client_ssl_ctx;        /* SSL context for client connections */
    struct socket client;           /* Connected client */
    time_t birth_time;              /* Time when request was received */
    int64_t num_bytes_sent;         /* Total bytes sent to client */
    int64_t content_len;            /* Content-Length header value */
    int64_t consumed_content;       /* How many bytes of content have been read */
    char *buf;                      /* Buffer for received data */
    char *path_info;                /* PATH_INFO part of the URL */
    int must_close;                 /* 1 if connection must be closed */
    int in_error_handler;           /* 1 if in handler for user defined error pages */
    int buf_size;                   /* Buffer size */
    int request_len;                /* Size of the request + headers in a buffer */
    int data_len;                   /* Total size of data in a buffer */
    int status_code;                /* HTTP reply status code, e.g. 200 */
    int throttle;                   /* Throttling, bytes/sec. <= 0 means no throttle */
    time_t last_throttle_time;      /* Last time throttled data was sent */
    int64_t last_throttle_bytes;    /* Bytes sent this second */
    pthread_mutex_t mutex;          /* Used by mg_lock_connection/mg_unlock_connection to ensure atomic transmissions for websockets */
};

typedef struct _keyvalue {
	char *kv_key;
	char *kv_val;
	timer_t kv_tmr;
	UT_hash_handle hh;
} _keyvalue, *keyvalue;

#ifdef SCRIPT_CACHE
typedef struct _script_data {
	char *key;
	ph7_vm *engine;
	UT_hash_handle hh;
} *script_data;
#endif
