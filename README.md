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
- Enables and/or disables `xp_cmdshell` 
- Executes system commands
- Crawls database links
- Command autocomplete 
- Easy to add new commands
- verbose mode prints background SQL queries
- debug mode prints ruby hashes from SQL queries result


## Requirements
```
gem install sequel terminal-table pry
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

Command             Description
-------             -----------
query               query <QUERY> - send raw query to the database.
query-link          query-link <LINK> <QUERY> - send raw query to the database.
info                info - retrieve server information.
whoami              whoami - retrieve current user informaiton.
db-admins           db-admins - retrieve sysadmins.
logons              logons - retrieve logged-on users.
sessions            sessions - retrieve sessions (includes usernames and hostnames).
enum-domain-groups  enum-domain-groups [DOMAIN]- retrieve domain groups.
dbs                 dbs - list databases.
tables              tables <DB_Name> - list tables for database.
columns             columns <Table_Name> - list columns from table.
exec                exec <CMD> - Execute Windows commands using xp_cmdshell.
cat                 cat <FILE> - Read file from disk. (full path must given)
enable-xpcmdshell   enable-xpcmdshell - enable xp_cmdshell on MSSQL.
disable-xpcmdshell  disable-xpcmdshell - disable xp_cmdshell on MSSQL.
links               links - crawl MSSQL links.
verbose             verbose [true | false] - show queries behind built-in commands.
debug               debug [true | false] - show queries values behind executed queries.
help                Show this screen
exit                exit the console


SQL -> 
```

## Contribution 
You are welcome to
- Enhance the code and/or queries 
- Add new commands
