# **Cynogale**

Cynogale combines:
* the [Civetweb](https://github.com/bel2125/civetweb) embeddable webserver
* the [PH7](https://github.com/symisc/PH7) embeddable PHP5 compiler 
* the [uthash](https://github.com/troydhanson/uthash) library
* the [Sqlite 3](http://www.sqlite.org) ebeddable database (optional)

...into a lighweight PHP5 webserver with an expiring key-value store and optional Sqlite database access

## Features
* serve static files
* similar to CGI, but PHP is compiled and executed inside a Civetweb thread worker
* **$_GET,** **$_POST**, **$_SERVER**, and **$_HEADER** provided on each request
* built-in expiring key-value store based on uthash, supports persistent keys
* optional Sqlite3 support
* optional PHP script caching
* MIT license

## Dependencies
* [Civetweb](https://github.com/bel2125/civetweb)
* [PH7](https://github.com/symisc/PH7)
* [uthash](https://github.com/troydhanson/uthash)
* [Sqlite 3](http://www.sqlite.org) (optional - recommend using your distro's shared library and header)
* Linux 2.6+ (tested on Debian 7 x86 w/ kernel 3.2)

## Caveats
* PHP5 support omits some PHP5 features, like preg_replace, DBO, and modules support
* uses threads and read-write locks extensively


## Instructions
* symlink **include/civetweb.h**, **src/civetweb.c**, and **src/md5.inl** to the Cynogale directory
* symlink **ph7.h** and **ph7.c** to the Cynogale directory
* copy or symlink **uthash.h** to the Cynogale directory, or make it available in the compiler search path
* if your distro/system doesn't have sqlite as a package, see below for instructions on how to create a shared libray
* optional - create and add PH7 foreign function bindings (see **main.c** and **sqlite.inl** for an example)
* edit **config.h** to suit
  * **HOME** base directory
  * **ROOT** document root relative to **HOME**
  * **PORT** listening port (see Civetweb docs for SSL and interface binding)
  * **NTHR** number of worker threads for Civetweb
  * **IMPP** import path for PHP scripts (require,etc)
* edit **Makefile** to suit - points of interest are **-O3**, **-DUSE_SQLITE**, and **-DSCRIPT_CACHE**
* **make**
* optionally, strip the executable and/or copy it somewhere in your **PATH**


## Sqlite shared library HOWTO
* obtain the Sqlite3 amalagation
* **gcc -O3 -c sqlite3.c**
* **ld -shared -o libsqlite3.so sqlite3.o**
* **cp sqlite3.h /usr/local/include** 
* **cp libsqlite3.so /usr/local/lib** 


## TODO
* add SSL options to **Makefile** and **config.h**
* possible ini-parser
* fix a few unguarded **malloc** calls
* investigate adding **malloc** guards to uthash

## License Compliance
Cynogale provides all sources, and is therefore compilant with the Symisc Public License


## Author
* Steven G. Messervey [sgmesservey@gmx.com](mailto:sgmesservey@gmx.com)
