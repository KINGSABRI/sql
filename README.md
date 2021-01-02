# sql

a console-based tool to connect to MSSQL server (loaded with pre-built queries) for red teamer and pentesters

## Features
- Acts as SQL UI, sends raw SQL query to MSSQL server
- Enumerates MSSQL server information 
- Enumerates current user information
- Enumerates logged-in users
- Enumerates database admins 
- Enumerates connected servers
- Enumerates exist databases
- Enumerates databases tables and columns 
- Enumerates impersontable users
- Enables and/or disables `xp_cmdshell` 
- Executes system commands
- Tree list for directories contents and UNC for capturing NTLMv2 hash or NTLM-relay
- Impersonates user
- Read file content
- Create directory and subdirectory recursively 
- Download files from MSSQL server system to local system
- Crawls database links
- Command autocompletion
- Easy to add new commands
- verbose mode prints background SQL queries
- debug mode prints ruby hashes from SQL queries result


## Requirements

Install tiny_tds dependency 
```
apt-get install freetds-dev
```

```
gem install sequel tiny_tds terminal-table pry
```

## Usage

### Command Menu
```
$ ruby sql.rb 

Usage: sql.rb [options]
    -H, --host <HOST>                MSSQL server hostname or IP address.
    -P, --port [PORT]                MSSQL port (default: 1433).
    -D, --database [PASSWORD]        Database name (optional).
    -u, --user <[DOMAIN\\]USER>      MSSQL username (double backslash for domain user: DOMAIN\\USER).
    -p, --pass <PASSWORD>            MSSQL password.
    -h, --help                       Print this message.
```

### Console Menue
```
$ ruby sql.rb --host MSSQL-SERVER -P 1433 -u DOMAIN\\USER -p PASSWORD
[+] Connected to '127.0.0.1:1433'.
¡] run 'help' to list avilable commands.
SQL -> help 

Command             Description
-------             -----------
--[ Main ]---------------------
query               query <QUERY> - send raw query to the database.
query-link          query-link <LINK> <QUERY> - send raw query to the database.
verbose             verbose [true | false] - show queries behind built-in commands.
debug               debug [true | false] - show queries values behind executed queries.
help                Show this screen
exit                exit the console
--[ System ]-------------------
exec                exec <CMD> - Execute Windows commands using xp_cmdshell.
cat                 cat <FILE> - Read file from disk. (full path must given)
mkdir               mkdir <DIR> - Create directories and subdirectories (acts like mkdir -p). (full path must given)
dirtree             dirtree <UNC> - Execute xp_dirtree to list local or remote(UNC) system's files & directories. UNC path can be used to capture NTLMv2 hash or NTLM-relay.
download            download <FILE> - Download files from MSSQL server system. (full path must given)
--[ DB & SQL Service ]---------
impersonate-login   impersonate-login <USER> - impersonate login user
impersonate-user    impersonate-login <USER> <DB> - impersonate database user (default: user='dbo', db='msdb')
enable-xpcmdshell   enable-xpcmdshell - enable xp_cmdshell on MSSQL.
disable-xpcmdshell  disable-xpcmdshell - disable xp_cmdshell on MSSQL.
--[ Enumuration ]-------------
info                info - retrieve server information.
whoami              whoami - retrieve current user informaiton.
db-admins           db-admins - retrieve sysadmins.
logons              logons - retrieve logged-on users.
sessions            sessions - retrieve sessions (includes usernames and hostnames).
enum-users          enum-users [NUM=10] - retrieve database users by id (default: first 0-10).
enum-domain-groups  enum-domain-groups [DOMAIN]- retrieve domain groups.
enum-impersonation  enum-impersonation - enumerate impersonationable users.
dbs                 dbs - list databases.
tables              tables <DB_Name> - list tables for database.
columns             columns <Table_Name> - list columns from table.
links               links - crawl MSSQL links.

SQL -> 
```

## Contribution 
You are welcome to
- Enhance the code and/or queries 
- Add new commands
