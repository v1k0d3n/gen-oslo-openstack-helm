[DEFAULT]

#
# From keystone
#

# Using this feature is *NOT* recommended. Instead, use the `keystone-manage
# bootstrap` command. The value of this option is treated as a "shared secret"
# that can be used to bootstrap Keystone through the API. This "token" does not
# represent a user (it has no identity), and carries no explicit authorization
# (it effectively bypasses most authorization checks). If set to `None`, the
# value is ignored and the `admin_token` middleware is effectively disabled.
# However, to completely disable `admin_token` in production (highly
# recommended, as it presents a security risk), remove
# `AdminTokenAuthMiddleware` (the `admin_token_auth` filter) from your paste
# application pipelines (for example, in `keystone-paste.ini`). (string value)
# from .Values.conf.keystone.admin_token
{{ if not .Values.conf.keystone.admin_token }}#{{ end }}admin_token = {{ .Values.conf.keystone.admin_token | default "<None>" }}

# The base public endpoint URL for Keystone that is advertised to clients
# (NOTE: this does NOT affect how Keystone listens for connections). Defaults
# to the base host URL of the request. For example, if keystone receives a
# request to `http://server:5000/v3/users`, then this will option will be
# automatically treated as `http://server:5000`. You should only need to set
# option if either the value of the base URL contains a path that keystone does
# not automatically infer (`/prefix/v3`), or if the endpoint should be found on
# a different host. (uri value)
# from .Values.conf.keystone.public_endpoint
{{ if not .Values.conf.keystone.public_endpoint }}#{{ end }}public_endpoint = {{ .Values.conf.keystone.public_endpoint | default "<None>" }}

# The base admin endpoint URL for Keystone that is advertised to clients (NOTE:
# this does NOT affect how Keystone listens for connections). Defaults to the
# base host URL of the request. For example, if keystone receives a request to
# `http://server:35357/v3/users`, then this will option will be automatically
# treated as `http://server:35357`. You should only need to set option if
# either the value of the base URL contains a path that keystone does not
# automatically infer (`/prefix/v3`), or if the endpoint should be found on a
# different host. (uri value)
# from .Values.conf.keystone.admin_endpoint
{{ if not .Values.conf.keystone.admin_endpoint }}#{{ end }}admin_endpoint = {{ .Values.conf.keystone.admin_endpoint | default "<None>" }}

# Maximum depth of the project hierarchy, excluding the project acting as a
# domain at the top of the hierarchy. WARNING: Setting it to a large value may
# adversely impact performance. (integer value)
# from .Values.conf.keystone.max_project_tree_depth
{{ if not .Values.conf.keystone.max_project_tree_depth }}#{{ end }}max_project_tree_depth = {{ .Values.conf.keystone.max_project_tree_depth | default "5" }}

# Limit the sizes of user & project ID/names. (integer value)
# from .Values.conf.keystone.max_param_size
{{ if not .Values.conf.keystone.max_param_size }}#{{ end }}max_param_size = {{ .Values.conf.keystone.max_param_size | default "64" }}

# Similar to `[DEFAULT] max_param_size`, but provides an exception for token
# values. With Fernet tokens, this can be set as low as 255. With UUID tokens,
# this should be set to 32). (integer value)
# from .Values.conf.keystone.max_token_size
{{ if not .Values.conf.keystone.max_token_size }}#{{ end }}max_token_size = {{ .Values.conf.keystone.max_token_size | default "255" }}

# Similar to the `[DEFAULT] member_role_name` option, this represents the
# default role ID used to associate users with their default projects in the v2
# API. This will be used as the explicit role where one is not specified by the
# v2 API. You do not need to set this value unless you want keystone to use an
# existing role with a different ID, other than the arbitrarily defined
# `_member_` role (in which case, you should set `[DEFAULT] member_role_name`
# as well). (string value)
# from .Values.conf.keystone.member_role_id
{{ if not .Values.conf.keystone.member_role_id }}#{{ end }}member_role_id = {{ .Values.conf.keystone.member_role_id | default "9fe2ff9ee4384b1894a90878d3e92bab" }}

# This is the role name used in combination with the `[DEFAULT] member_role_id`
# option; see that option for more detail. You do not need to set this option
# unless you want keystone to use an existing role (in which case, you should
# set `[DEFAULT] member_role_id` as well). (string value)
# from .Values.conf.keystone.member_role_name
{{ if not .Values.conf.keystone.member_role_name }}#{{ end }}member_role_name = {{ .Values.conf.keystone.member_role_name | default "_member_" }}

# The value passed as the keyword "rounds" to passlib's encrypt method. This
# option represents a trade off between security and performance. Higher values
# lead to slower performance, but higher security. Changing this option will
# only affect newly created passwords as existing password hashes already have
# a fixed number of rounds applied, so it is safe to tune this option in a
# running cluster. For more information, see
# https://pythonhosted.org/passlib/password_hash_api.html#choosing-the-right-
# rounds-value (integer value)
# Minimum value: 1000
# Maximum value: 100000
# from .Values.conf.keystone.crypt_strength
{{ if not .Values.conf.keystone.crypt_strength }}#{{ end }}crypt_strength = {{ .Values.conf.keystone.crypt_strength | default "10000" }}

# The maximum number of entities that will be returned in a collection. This
# global limit may be then overridden for a specific driver, by specifying a
# list_limit in the appropriate section (for example, `[assignment]`). No limit
# is set by default. In larger deployments, it is recommended that you set this
# to a reasonable number to prevent operations like listing all users and
# projects from placing an unnecessary load on the system. (integer value)
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}

# If set to true, strict password length checking is performed for password
# manipulation. If a password exceeds the maximum length, the operation will
# fail with an HTTP 403 Forbidden error. If set to false, passwords are
# automatically truncated to the maximum length. (boolean value)
# from .Values.conf.keystone.strict_password_check
{{ if not .Values.conf.keystone.strict_password_check }}#{{ end }}strict_password_check = {{ .Values.conf.keystone.strict_password_check | default "false" }}

# DEPRECATED: The HTTP header used to determine the scheme for the original
# request, even if it was removed by an SSL terminating proxy. (string value)
# This option is deprecated for removal since N.
# Its value may be silently ignored in the future.
# Reason: This option has been deprecated in the N release and will be removed
# in the P release. Use oslo.middleware.http_proxy_to_wsgi configuration
# instead.
# from .Values.conf.keystone.secure_proxy_ssl_header
{{ if not .Values.conf.keystone.secure_proxy_ssl_header }}#{{ end }}secure_proxy_ssl_header = {{ .Values.conf.keystone.secure_proxy_ssl_header | default "HTTP_X_FORWARDED_PROTO" }}

# If set to true, then the server will return information in HTTP responses
# that may allow an unauthenticated or authenticated user to get more
# information than normal, such as additional details about why authentication
# failed. This may be useful for debugging but is insecure. (boolean value)
# from .Values.conf.keystone.insecure_debug
{{ if not .Values.conf.keystone.insecure_debug }}#{{ end }}insecure_debug = {{ .Values.conf.keystone.insecure_debug | default "false" }}

# Default `publisher_id` for outgoing notifications. If left undefined,
# Keystone will default to using the server's host name. (string value)
# from .Values.conf.keystone.default_publisher_id
{{ if not .Values.conf.keystone.default_publisher_id }}#{{ end }}default_publisher_id = {{ .Values.conf.keystone.default_publisher_id | default "<None>" }}

# Define the notification format for identity service events. A `basic`
# notification only has information about the resource being operated on. A
# `cadf` notification has the same information, as well as information about
# the initiator of the event. The `cadf` option is entirely backwards
# compatible with the `basic` option, but is fully CADF-compliant, and is
# recommended for auditing use cases. (string value)
# Allowed values: basic, cadf
# from .Values.conf.keystone.notification_format
{{ if not .Values.conf.keystone.notification_format }}#{{ end }}notification_format = {{ .Values.conf.keystone.notification_format | default "cadf" }}

# You can reduce the number of notifications keystone emits by explicitly
# opting out. Keystone will not emit notifications that match the patterns
# expressed in this list. Values are expected to be in the form of
# `identity.<resource_type>.<operation>`. By default, all notifications related
# to authentication are automatically suppressed. This field can be set
# multiple times in order to opt-out of multiple notification topics. For
# example, the following suppresses notifications describing user creation or
# successful authentication events: notification_opt_out=identity.user.create
# notification_opt_out=identity.authenticate.success (multi valued)
# from .Values.conf.keystone.notification_opt_out
{{ if not .Values.conf.keystone.notification_opt_out }}#{{ end }}notification_opt_out = {{ .Values.conf.keystone.notification_opt_out | default "identity.authenticate.success" }}
# from .Values.conf.keystone.notification_opt_out
{{ if not .Values.conf.keystone.notification_opt_out }}#{{ end }}notification_opt_out = {{ .Values.conf.keystone.notification_opt_out | default "identity.authenticate.pending" }}
# from .Values.conf.keystone.notification_opt_out
{{ if not .Values.conf.keystone.notification_opt_out }}#{{ end }}notification_opt_out = {{ .Values.conf.keystone.notification_opt_out | default "identity.authenticate.failed" }}

#
# From oslo.log
#

# If set to true, the logging level will be set to DEBUG instead of the default
# INFO level. (boolean value)
# Note: This option can be changed without restarting.
# from .Values.conf.oslo.log.debug
{{ if not .Values.conf.oslo.log.debug }}#{{ end }}debug = {{ .Values.conf.oslo.log.debug | default "false" }}

# DEPRECATED: If set to false, the logging level will be set to WARNING instead
# of the default INFO level. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .Values.conf.oslo.log.verbose
{{ if not .Values.conf.oslo.log.verbose }}#{{ end }}verbose = {{ .Values.conf.oslo.log.verbose | default "true" }}

# The name of a logging configuration file. This file is appended to any
# existing logging configuration files. For details about logging configuration
# files, see the Python logging module documentation. Note that when logging
# configuration files are used then all logging configuration is set in the
# configuration file and other logging configuration options are ignored (for
# example, logging_context_format_string). (string value)
# Note: This option can be changed without restarting.
# Deprecated group/name - [DEFAULT]/log_config
# from .Values.conf.oslo.log.log_config_append
{{ if not .Values.conf.oslo.log.log_config_append }}#{{ end }}log_config_append = {{ .Values.conf.oslo.log.log_config_append | default "<None>" }}

# Defines the format string for %%(asctime)s in log records. Default:
# %(default)s . This option is ignored if log_config_append is set. (string
# value)
# from .Values.conf.oslo.log.log_date_format
{{ if not .Values.conf.oslo.log.log_date_format }}#{{ end }}log_date_format = {{ .Values.conf.oslo.log.log_date_format | default "%Y-%m-%d %H:%M:%S" }}

# (Optional) Name of log file to send logging output to. If no default is set,
# logging will go to stderr as defined by use_stderr. This option is ignored if
# log_config_append is set. (string value)
# Deprecated group/name - [DEFAULT]/logfile
# from .Values.conf.oslo.log.log_file
{{ if not .Values.conf.oslo.log.log_file }}#{{ end }}log_file = {{ .Values.conf.oslo.log.log_file | default "<None>" }}

# (Optional) The base directory used for relative log_file  paths. This option
# is ignored if log_config_append is set. (string value)
# Deprecated group/name - [DEFAULT]/logdir
# from .Values.conf.oslo.log.log_dir
{{ if not .Values.conf.oslo.log.log_dir }}#{{ end }}log_dir = {{ .Values.conf.oslo.log.log_dir | default "<None>" }}

# Uses logging handler designed to watch file system. When log file is moved or
# removed this handler will open a new log file with specified path
# instantaneously. It makes sense only if log_file option is specified and
# Linux platform is used. This option is ignored if log_config_append is set.
# (boolean value)
# from .Values.conf.oslo.log.watch_log_file
{{ if not .Values.conf.oslo.log.watch_log_file }}#{{ end }}watch_log_file = {{ .Values.conf.oslo.log.watch_log_file | default "false" }}

# Use syslog for logging. Existing syslog format is DEPRECATED and will be
# changed later to honor RFC5424. This option is ignored if log_config_append
# is set. (boolean value)
# from .Values.conf.oslo.log.use_syslog
{{ if not .Values.conf.oslo.log.use_syslog }}#{{ end }}use_syslog = {{ .Values.conf.oslo.log.use_syslog | default "false" }}

# Syslog facility to receive log lines. This option is ignored if
# log_config_append is set. (string value)
# from .Values.conf.oslo.log.syslog_log_facility
{{ if not .Values.conf.oslo.log.syslog_log_facility }}#{{ end }}syslog_log_facility = {{ .Values.conf.oslo.log.syslog_log_facility | default "LOG_USER" }}

# Log output to standard error. This option is ignored if log_config_append is
# set. (boolean value)
# from .Values.conf.oslo.log.use_stderr
{{ if not .Values.conf.oslo.log.use_stderr }}#{{ end }}use_stderr = {{ .Values.conf.oslo.log.use_stderr | default "false" }}

# Format string to use for log messages with context. (string value)
# from .Values.conf.oslo.log.logging_context_format_string
{{ if not .Values.conf.oslo.log.logging_context_format_string }}#{{ end }}logging_context_format_string = {{ .Values.conf.oslo.log.logging_context_format_string | default "%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [%(request_id)s %(user_identity)s] %(instance)s%(message)s" }}

# Format string to use for log messages when context is undefined. (string
# value)
# from .Values.conf.oslo.log.logging_default_format_string
{{ if not .Values.conf.oslo.log.logging_default_format_string }}#{{ end }}logging_default_format_string = {{ .Values.conf.oslo.log.logging_default_format_string | default "%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [-] %(instance)s%(message)s" }}

# Additional data to append to log message when logging level for the message
# is DEBUG. (string value)
# from .Values.conf.oslo.log.logging_debug_format_suffix
{{ if not .Values.conf.oslo.log.logging_debug_format_suffix }}#{{ end }}logging_debug_format_suffix = {{ .Values.conf.oslo.log.logging_debug_format_suffix | default "%(funcName)s %(pathname)s:%(lineno)d" }}

# Prefix each line of exception output with this format. (string value)
# from .Values.conf.oslo.log.logging_exception_prefix
{{ if not .Values.conf.oslo.log.logging_exception_prefix }}#{{ end }}logging_exception_prefix = {{ .Values.conf.oslo.log.logging_exception_prefix | default "%(asctime)s.%(msecs)03d %(process)d ERROR %(name)s %(instance)s" }}

# Defines the format string for %(user_identity)s that is used in
# logging_context_format_string. (string value)
# from .Values.conf.oslo.log.logging_user_identity_format
{{ if not .Values.conf.oslo.log.logging_user_identity_format }}#{{ end }}logging_user_identity_format = {{ .Values.conf.oslo.log.logging_user_identity_format | default "%(user)s %(tenant)s %(domain)s %(user_domain)s %(project_domain)s" }}

# List of package logging levels in logger=LEVEL pairs. This option is ignored
# if log_config_append is set. (list value)
# from .Values.conf.oslo.log.default_log_levels
{{ if not .Values.conf.oslo.log.default_log_levels }}#{{ end }}default_log_levels = {{ .Values.conf.oslo.log.default_log_levels | default "amqp=WARN,amqplib=WARN,boto=WARN,qpid=WARN,sqlalchemy=WARN,suds=INFO,oslo.messaging=INFO,iso8601=WARN,requests.packages.urllib3.connectionpool=WARN,urllib3.connectionpool=WARN,websocket=WARN,requests.packages.urllib3.util.retry=WARN,urllib3.util.retry=WARN,keystonemiddleware=WARN,routes.middleware=WARN,stevedore=WARN,taskflow=WARN,keystoneauth=WARN,oslo.cache=INFO,dogpile.core.dogpile=INFO" }}

# Enables or disables publication of error events. (boolean value)
# from .Values.conf.oslo.log.publish_errors
{{ if not .Values.conf.oslo.log.publish_errors }}#{{ end }}publish_errors = {{ .Values.conf.oslo.log.publish_errors | default "false" }}

# The format for an instance that is passed with the log message. (string
# value)
# from .Values.conf.oslo.log.instance_format
{{ if not .Values.conf.oslo.log.instance_format }}#{{ end }}instance_format = {{ .Values.conf.oslo.log.instance_format | default "\"[instance: %(uuid)s] \"" }}

# The format for an instance UUID that is passed with the log message. (string
# value)
# from .Values.conf.oslo.log.instance_uuid_format
{{ if not .Values.conf.oslo.log.instance_uuid_format }}#{{ end }}instance_uuid_format = {{ .Values.conf.oslo.log.instance_uuid_format | default "\"[instance: %(uuid)s] \"" }}

# Interval, number of seconds, of log rate limiting. (integer value)
# from .Values.conf.oslo.log.rate_limit_interval
{{ if not .Values.conf.oslo.log.rate_limit_interval }}#{{ end }}rate_limit_interval = {{ .Values.conf.oslo.log.rate_limit_interval | default "0" }}

# Maximum number of logged messages per rate_limit_interval. (integer value)
# from .Values.conf.oslo.log.rate_limit_burst
{{ if not .Values.conf.oslo.log.rate_limit_burst }}#{{ end }}rate_limit_burst = {{ .Values.conf.oslo.log.rate_limit_burst | default "0" }}

# Log level name used by rate limiting: CRITICAL, ERROR, INFO, WARNING, DEBUG
# or empty string. Logs with level greater or equal to rate_limit_except_level
# are not filtered. An empty string means that all levels are filtered. (string
# value)
# from .Values.conf.oslo.log.rate_limit_except_level
{{ if not .Values.conf.oslo.log.rate_limit_except_level }}#{{ end }}rate_limit_except_level = {{ .Values.conf.oslo.log.rate_limit_except_level | default "CRITICAL" }}

# Enables or disables fatal status of deprecations. (boolean value)
# from .Values.conf.oslo.log.fatal_deprecations
{{ if not .Values.conf.oslo.log.fatal_deprecations }}#{{ end }}fatal_deprecations = {{ .Values.conf.oslo.log.fatal_deprecations | default "false" }}

#
# From oslo.messaging
#

# Size of RPC connection pool. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_conn_pool_size
# from .Values.conf.oslo.messaging.rpc_conn_pool_size
{{ if not .Values.conf.oslo.messaging.rpc_conn_pool_size }}#{{ end }}rpc_conn_pool_size = {{ .Values.conf.oslo.messaging.rpc_conn_pool_size | default "30" }}

# The pool size limit for connections expiration policy (integer value)
# from .Values.conf.oslo.messaging.conn_pool_min_size
{{ if not .Values.conf.oslo.messaging.conn_pool_min_size }}#{{ end }}conn_pool_min_size = {{ .Values.conf.oslo.messaging.conn_pool_min_size | default "2" }}

# The time-to-live in sec of idle connections in the pool (integer value)
# from .Values.conf.oslo.messaging.conn_pool_ttl
{{ if not .Values.conf.oslo.messaging.conn_pool_ttl }}#{{ end }}conn_pool_ttl = {{ .Values.conf.oslo.messaging.conn_pool_ttl | default "1200" }}

# ZeroMQ bind address. Should be a wildcard (*), an ethernet interface, or IP.
# The "host" option should point or resolve to this address. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_address
# from .Values.conf.oslo.messaging.rpc_zmq_bind_address
{{ if not .Values.conf.oslo.messaging.rpc_zmq_bind_address }}#{{ end }}rpc_zmq_bind_address = {{ .Values.conf.oslo.messaging.rpc_zmq_bind_address | default "*" }}

# MatchMaker driver. (string value)
# Allowed values: redis, sentinel, dummy
# Deprecated group/name - [DEFAULT]/rpc_zmq_matchmaker
# from .Values.conf.oslo.messaging.rpc_zmq_matchmaker
{{ if not .Values.conf.oslo.messaging.rpc_zmq_matchmaker }}#{{ end }}rpc_zmq_matchmaker = {{ .Values.conf.oslo.messaging.rpc_zmq_matchmaker | default "redis" }}

# Number of ZeroMQ contexts, defaults to 1. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_contexts
# from .Values.conf.oslo.messaging.rpc_zmq_contexts
{{ if not .Values.conf.oslo.messaging.rpc_zmq_contexts }}#{{ end }}rpc_zmq_contexts = {{ .Values.conf.oslo.messaging.rpc_zmq_contexts | default "1" }}

# Maximum number of ingress messages to locally buffer per topic. Default is
# unlimited. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_topic_backlog
# from .Values.conf.oslo.messaging.rpc_zmq_topic_backlog
{{ if not .Values.conf.oslo.messaging.rpc_zmq_topic_backlog }}#{{ end }}rpc_zmq_topic_backlog = {{ .Values.conf.oslo.messaging.rpc_zmq_topic_backlog | default "<None>" }}

# Directory for holding IPC sockets. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_ipc_dir
# from .Values.conf.oslo.messaging.rpc_zmq_ipc_dir
{{ if not .Values.conf.oslo.messaging.rpc_zmq_ipc_dir }}#{{ end }}rpc_zmq_ipc_dir = {{ .Values.conf.oslo.messaging.rpc_zmq_ipc_dir | default "/var/run/openstack" }}

# Name of this node. Must be a valid hostname, FQDN, or IP address. Must match
# "host" option, if running Nova. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_host
# from .Values.conf.oslo.messaging.rpc_zmq_host
{{ if not .Values.conf.oslo.messaging.rpc_zmq_host }}#{{ end }}rpc_zmq_host = {{ .Values.conf.oslo.messaging.rpc_zmq_host | default "localhost" }}

# Number of seconds to wait before all pending messages will be sent after
# closing a socket. The default value of -1 specifies an infinite linger
# period. The value of 0 specifies no linger period. Pending messages shall be
# discarded immediately when the socket is closed. Positive values specify an
# upper bound for the linger period. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_cast_timeout
# from .Values.conf.oslo.messaging.zmq_linger
{{ if not .Values.conf.oslo.messaging.zmq_linger }}#{{ end }}zmq_linger = {{ .Values.conf.oslo.messaging.zmq_linger | default "-1" }}

# The default number of seconds that poll should wait. Poll raises timeout
# exception when timeout expired. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_poll_timeout
# from .Values.conf.oslo.messaging.rpc_poll_timeout
{{ if not .Values.conf.oslo.messaging.rpc_poll_timeout }}#{{ end }}rpc_poll_timeout = {{ .Values.conf.oslo.messaging.rpc_poll_timeout | default "1" }}

# Expiration timeout in seconds of a name service record about existing target
# ( < 0 means no timeout). (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_expire
# from .Values.conf.oslo.messaging.zmq_target_expire
{{ if not .Values.conf.oslo.messaging.zmq_target_expire }}#{{ end }}zmq_target_expire = {{ .Values.conf.oslo.messaging.zmq_target_expire | default "300" }}

# Update period in seconds of a name service record about existing target.
# (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_update
# from .Values.conf.oslo.messaging.zmq_target_update
{{ if not .Values.conf.oslo.messaging.zmq_target_update }}#{{ end }}zmq_target_update = {{ .Values.conf.oslo.messaging.zmq_target_update | default "180" }}

# Use PUB/SUB pattern for fanout methods. PUB/SUB always uses proxy. (boolean
# value)
# Deprecated group/name - [DEFAULT]/use_pub_sub
# from .Values.conf.oslo.messaging.use_pub_sub
{{ if not .Values.conf.oslo.messaging.use_pub_sub }}#{{ end }}use_pub_sub = {{ .Values.conf.oslo.messaging.use_pub_sub | default "false" }}

# Use ROUTER remote proxy. (boolean value)
# Deprecated group/name - [DEFAULT]/use_router_proxy
# from .Values.conf.oslo.messaging.use_router_proxy
{{ if not .Values.conf.oslo.messaging.use_router_proxy }}#{{ end }}use_router_proxy = {{ .Values.conf.oslo.messaging.use_router_proxy | default "false" }}

# This option makes direct connections dynamic or static. It makes sense only
# with use_router_proxy=False which means to use direct connections for direct
# message types (ignored otherwise). (boolean value)
# from .Values.conf.oslo.messaging.use_dynamic_connections
{{ if not .Values.conf.oslo.messaging.use_dynamic_connections }}#{{ end }}use_dynamic_connections = {{ .Values.conf.oslo.messaging.use_dynamic_connections | default "false" }}

# How many additional connections to a host will be made for failover reasons.
# This option is actual only in dynamic connections mode. (integer value)
# from .Values.conf.oslo.messaging.zmq_failover_connections
{{ if not .Values.conf.oslo.messaging.zmq_failover_connections }}#{{ end }}zmq_failover_connections = {{ .Values.conf.oslo.messaging.zmq_failover_connections | default "2" }}

# Minimal port number for random ports range. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rpc_zmq_min_port
# from .Values.conf.oslo.messaging.rpc_zmq_min_port
{{ if not .Values.conf.oslo.messaging.rpc_zmq_min_port }}#{{ end }}rpc_zmq_min_port = {{ .Values.conf.oslo.messaging.rpc_zmq_min_port | default "49153" }}

# Maximal port number for random ports range. (integer value)
# Minimum value: 1
# Maximum value: 65536
# Deprecated group/name - [DEFAULT]/rpc_zmq_max_port
# from .Values.conf.oslo.messaging.rpc_zmq_max_port
{{ if not .Values.conf.oslo.messaging.rpc_zmq_max_port }}#{{ end }}rpc_zmq_max_port = {{ .Values.conf.oslo.messaging.rpc_zmq_max_port | default "65536" }}

# Number of retries to find free port number before fail with ZMQBindError.
# (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_port_retries
# from .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries
{{ if not .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries }}#{{ end }}rpc_zmq_bind_port_retries = {{ .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries | default "100" }}

# Default serialization mechanism for serializing/deserializing
# outgoing/incoming messages (string value)
# Allowed values: json, msgpack
# Deprecated group/name - [DEFAULT]/rpc_zmq_serialization
# from .Values.conf.oslo.messaging.rpc_zmq_serialization
{{ if not .Values.conf.oslo.messaging.rpc_zmq_serialization }}#{{ end }}rpc_zmq_serialization = {{ .Values.conf.oslo.messaging.rpc_zmq_serialization | default "json" }}

# This option configures round-robin mode in zmq socket. True means not keeping
# a queue when server side disconnects. False means to keep queue and messages
# even if server is disconnected, when the server appears we send all
# accumulated messages to it. (boolean value)
# from .Values.conf.oslo.messaging.zmq_immediate
{{ if not .Values.conf.oslo.messaging.zmq_immediate }}#{{ end }}zmq_immediate = {{ .Values.conf.oslo.messaging.zmq_immediate | default "true" }}

# Enable/disable TCP keepalive (KA) mechanism. The default value of -1 (or any
# other negative value) means to skip any overrides and leave it to OS default;
# 0 and 1 (or any other positive value) mean to disable and enable the option
# respectively. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive }}#{{ end }}zmq_tcp_keepalive = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive | default "-1" }}

# The duration between two keepalive transmissions in idle condition. The unit
# is platform dependent, for example, seconds in Linux, milliseconds in Windows
# etc. The default value of -1 (or any other negative value and 0) means to
# skip any overrides and leave it to OS default. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle }}#{{ end }}zmq_tcp_keepalive_idle = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle | default "-1" }}

# The number of retransmissions to be carried out before declaring that remote
# end is not available. The default value of -1 (or any other negative value
# and 0) means to skip any overrides and leave it to OS default. (integer
# value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt }}#{{ end }}zmq_tcp_keepalive_cnt = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt | default "-1" }}

# The duration between two successive keepalive retransmissions, if
# acknowledgement to the previous keepalive transmission is not received. The
# unit is platform dependent, for example, seconds in Linux, milliseconds in
# Windows etc. The default value of -1 (or any other negative value and 0)
# means to skip any overrides and leave it to OS default. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl }}#{{ end }}zmq_tcp_keepalive_intvl = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl | default "-1" }}

# Maximum number of (green) threads to work concurrently. (integer value)
# from .Values.conf.oslo.messaging.rpc_thread_pool_size
{{ if not .Values.conf.oslo.messaging.rpc_thread_pool_size }}#{{ end }}rpc_thread_pool_size = {{ .Values.conf.oslo.messaging.rpc_thread_pool_size | default "100" }}

# Expiration timeout in seconds of a sent/received message after which it is
# not tracked anymore by a client/server. (integer value)
# from .Values.conf.oslo.messaging.rpc_message_ttl
{{ if not .Values.conf.oslo.messaging.rpc_message_ttl }}#{{ end }}rpc_message_ttl = {{ .Values.conf.oslo.messaging.rpc_message_ttl | default "300" }}

# Wait for message acknowledgements from receivers. This mechanism works only
# via proxy without PUB/SUB. (boolean value)
# from .Values.conf.oslo.messaging.rpc_use_acks
{{ if not .Values.conf.oslo.messaging.rpc_use_acks }}#{{ end }}rpc_use_acks = {{ .Values.conf.oslo.messaging.rpc_use_acks | default "false" }}

# Number of seconds to wait for an ack from a cast/call. After each retry
# attempt this timeout is multiplied by some specified multiplier. (integer
# value)
# from .Values.conf.oslo.messaging.rpc_ack_timeout_base
{{ if not .Values.conf.oslo.messaging.rpc_ack_timeout_base }}#{{ end }}rpc_ack_timeout_base = {{ .Values.conf.oslo.messaging.rpc_ack_timeout_base | default "15" }}

# Number to multiply base ack timeout by after each retry attempt. (integer
# value)
# from .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier
{{ if not .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier }}#{{ end }}rpc_ack_timeout_multiplier = {{ .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier | default "2" }}

# Default number of message sending attempts in case of any problems occurred:
# positive value N means at most N retries, 0 means no retries, None or -1 (or
# any other negative values) mean to retry forever. This option is used only if
# acknowledgments are enabled. (integer value)
# from .Values.conf.oslo.messaging.rpc_retry_attempts
{{ if not .Values.conf.oslo.messaging.rpc_retry_attempts }}#{{ end }}rpc_retry_attempts = {{ .Values.conf.oslo.messaging.rpc_retry_attempts | default "3" }}

# List of publisher hosts SubConsumer can subscribe on. This option has higher
# priority then the default publishers list taken from the matchmaker. (list
# value)
# from .Values.conf.oslo.messaging.subscribe_on
{{ if not .Values.conf.oslo.messaging.subscribe_on }}#{{ end }}subscribe_on = {{ .Values.conf.oslo.messaging.subscribe_on | default "" }}

# Size of executor thread pool. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_thread_pool_size
# from .Values.conf.oslo.messaging.executor_thread_pool_size
{{ if not .Values.conf.oslo.messaging.executor_thread_pool_size }}#{{ end }}executor_thread_pool_size = {{ .Values.conf.oslo.messaging.executor_thread_pool_size | default "64" }}

# Seconds to wait for a response from a call. (integer value)
# from .Values.conf.oslo.messaging.rpc_response_timeout
{{ if not .Values.conf.oslo.messaging.rpc_response_timeout }}#{{ end }}rpc_response_timeout = {{ .Values.conf.oslo.messaging.rpc_response_timeout | default "60" }}

# A URL representing the messaging driver to use and its full configuration.
# (string value)
# from .Values.conf.oslo.messaging.transport_url
{{ if not .Values.conf.oslo.messaging.transport_url }}#{{ end }}transport_url = {{ .Values.conf.oslo.messaging.transport_url | default "<None>" }}

# DEPRECATED: The messaging driver to use, defaults to rabbit. Other drivers
# include amqp and zmq. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rpc_backend
{{ if not .Values.conf.oslo.messaging.rpc_backend }}#{{ end }}rpc_backend = {{ .Values.conf.oslo.messaging.rpc_backend | default "rabbit" }}

# The default exchange under which topics are scoped. May be overridden by an
# exchange name specified in the transport_url option. (string value)
# from .Values.conf.oslo.messaging.control_exchange
{{ if not .Values.conf.oslo.messaging.control_exchange }}#{{ end }}control_exchange = {{ .Values.conf.oslo.messaging.control_exchange | default "keystone" }}


[assignment]

#
# From keystone
#

# Entry point for the assignment backend driver (where role assignments are
# stored) in the `keystone.assignment` namespace. Only a SQL driver is supplied
# by keystone itself. Unless you are writing proprietary drivers for keystone,
# you do not need to set this option. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# A list of role names which are prohibited from being an implied role. (list
# value)
# from .Values.conf.keystone.prohibited_implied_role
{{ if not .Values.conf.keystone.prohibited_implied_role }}#{{ end }}prohibited_implied_role = {{ .Values.conf.keystone.prohibited_implied_role | default "admin" }}


[auth]

#
# From keystone
#

# Allowed authentication methods. Note: You should disable the `external` auth
# method if you are currently using federation. External auth and federation
# both use the REMOTE_USER variable. Since both the mapped and external plugin
# are being invoked to validate attributes in the request environment, it can
# cause conflicts. (list value)
# from .Values.conf.keystone.methods
{{ if not .Values.conf.keystone.methods }}#{{ end }}methods = {{ .Values.conf.keystone.methods | default "external,password,token,oauth1,mapped" }}

# Entry point for the password auth plugin module in the
# `keystone.auth.password` namespace. You do not need to set this unless you
# are overriding keystone's own password authentication plugin. (string value)
# from .Values.conf.keystone.password
{{ if not .Values.conf.keystone.password }}#{{ end }}password = {{ .Values.conf.keystone.password | default "<None>" }}

# Entry point for the token auth plugin module in the `keystone.auth.token`
# namespace. You do not need to set this unless you are overriding keystone's
# own token authentication plugin. (string value)
# from .Values.conf.keystone.token
{{ if not .Values.conf.keystone.token }}#{{ end }}token = {{ .Values.conf.keystone.token | default "<None>" }}

# Entry point for the external (`REMOTE_USER`) auth plugin module in the
# `keystone.auth.external` namespace. Supplied drivers are `DefaultDomain` and
# `Domain`. The default driver is `DefaultDomain`, which assumes that all users
# identified by the username specified to keystone in the `REMOTE_USER`
# variable exist within the context of the default domain. The `Domain` option
# expects an additional environment variable be presented to keystone,
# `REMOTE_DOMAIN`, containing the domain name of the `REMOTE_USER` (if
# `REMOTE_DOMAIN` is not set, then the default domain will be used instead).
# You do not need to set this unless you are taking advantage of "external
# authentication", where the application server (such as Apache) is handling
# authentication instead of keystone. (string value)
# from .Values.conf.keystone.external
{{ if not .Values.conf.keystone.external }}#{{ end }}external = {{ .Values.conf.keystone.external | default "<None>" }}

# Entry point for the OAuth 1.0a auth plugin module in the
# `keystone.auth.oauth1` namespace. You do not need to set this unless you are
# overriding keystone's own `oauth1` authentication plugin. (string value)
# from .Values.conf.keystone.oauth1
{{ if not .Values.conf.keystone.oauth1 }}#{{ end }}oauth1 = {{ .Values.conf.keystone.oauth1 | default "<None>" }}

# Entry point for the mapped auth plugin module in the `keystone.auth.mapped`
# namespace. You do not need to set this unless you are overriding keystone's
# own `mapped` authentication plugin. (string value)
# from .Values.conf.keystone.mapped
{{ if not .Values.conf.keystone.mapped }}#{{ end }}mapped = {{ .Values.conf.keystone.mapped | default "<None>" }}


[cache]

#
# From oslo.cache
#

# Prefix for building the configuration dictionary for the cache region. This
# should not need to be changed unless there is another dogpile.cache region
# with the same configuration name. (string value)
# from .Values.conf.oslo.cache.config_prefix
{{ if not .Values.conf.oslo.cache.config_prefix }}#{{ end }}config_prefix = {{ .Values.conf.oslo.cache.config_prefix | default "cache.oslo" }}

# Default TTL, in seconds, for any cached item in the dogpile.cache region.
# This applies to any cached method that doesn't have an explicit cache
# expiration time defined for it. (integer value)
# from .Values.conf.oslo.cache.expiration_time
{{ if not .Values.conf.oslo.cache.expiration_time }}#{{ end }}expiration_time = {{ .Values.conf.oslo.cache.expiration_time | default "600" }}

# Dogpile.cache backend module. It is recommended that Memcache or Redis
# (dogpile.cache.redis) be used in production deployments. For eventlet-based
# or highly threaded servers, Memcache with pooling (oslo_cache.memcache_pool)
# is recommended. For low thread servers, dogpile.cache.memcached is
# recommended. Test environments with a single instance of the server can use
# the dogpile.cache.memory backend. (string value)
# from .Values.conf.oslo.cache.backend
{{ if not .Values.conf.oslo.cache.backend }}#{{ end }}backend = {{ .Values.conf.oslo.cache.backend | default "dogpile.cache.null" }}

# Arguments supplied to the backend module. Specify this option once per
# argument to be passed to the dogpile.cache backend. Example format:
# "<argname>:<value>". (multi valued)
# from .Values.conf.oslo.cache.backend_argument
{{ if not .Values.conf.oslo.cache.backend_argument }}#{{ end }}backend_argument = {{ .Values.conf.oslo.cache.backend_argument | default "" }}

# Proxy classes to import that will affect the way the dogpile.cache backend
# functions. See the dogpile.cache documentation on changing-backend-behavior.
# (list value)
# from .Values.conf.oslo.cache.proxies
{{ if not .Values.conf.oslo.cache.proxies }}#{{ end }}proxies = {{ .Values.conf.oslo.cache.proxies | default "" }}

# Global toggle for caching. (boolean value)
# from .Values.conf.oslo.cache.enabled
{{ if not .Values.conf.oslo.cache.enabled }}#{{ end }}enabled = {{ .Values.conf.oslo.cache.enabled | default "true" }}

# Extra debugging from the cache backend (cache keys, get/set/delete/etc
# calls). This is only really useful if you need to see the specific cache-
# backend get/set/delete calls with the keys/values.  Typically this should be
# left set to false. (boolean value)
# from .Values.conf.oslo.cache.debug_cache_backend
{{ if not .Values.conf.oslo.cache.debug_cache_backend }}#{{ end }}debug_cache_backend = {{ .Values.conf.oslo.cache.debug_cache_backend | default "false" }}

# Memcache servers in the format of "host:port". (dogpile.cache.memcache and
# oslo_cache.memcache_pool backends only). (list value)
# from .Values.conf.oslo.cache.memcache_servers
{{ if not .Values.conf.oslo.cache.memcache_servers }}#{{ end }}memcache_servers = {{ .Values.conf.oslo.cache.memcache_servers | default "localhost:11211" }}

# Number of seconds memcached server is considered dead before it is tried
# again. (dogpile.cache.memcache and oslo_cache.memcache_pool backends only).
# (integer value)
# from .Values.conf.oslo.cache.memcache_dead_retry
{{ if not .Values.conf.oslo.cache.memcache_dead_retry }}#{{ end }}memcache_dead_retry = {{ .Values.conf.oslo.cache.memcache_dead_retry | default "300" }}

# Timeout in seconds for every call to a server. (dogpile.cache.memcache and
# oslo_cache.memcache_pool backends only). (integer value)
# from .Values.conf.oslo.cache.memcache_socket_timeout
{{ if not .Values.conf.oslo.cache.memcache_socket_timeout }}#{{ end }}memcache_socket_timeout = {{ .Values.conf.oslo.cache.memcache_socket_timeout | default "3" }}

# Max total number of open connections to every memcached server.
# (oslo_cache.memcache_pool backend only). (integer value)
# from .Values.conf.oslo.cache.memcache_pool_maxsize
{{ if not .Values.conf.oslo.cache.memcache_pool_maxsize }}#{{ end }}memcache_pool_maxsize = {{ .Values.conf.oslo.cache.memcache_pool_maxsize | default "10" }}

# Number of seconds a connection to memcached is held unused in the pool before
# it is closed. (oslo_cache.memcache_pool backend only). (integer value)
# from .Values.conf.oslo.cache.memcache_pool_unused_timeout
{{ if not .Values.conf.oslo.cache.memcache_pool_unused_timeout }}#{{ end }}memcache_pool_unused_timeout = {{ .Values.conf.oslo.cache.memcache_pool_unused_timeout | default "60" }}

# Number of seconds that an operation will wait to get a memcache client
# connection. (integer value)
# from .Values.conf.oslo.cache.memcache_pool_connection_get_timeout
{{ if not .Values.conf.oslo.cache.memcache_pool_connection_get_timeout }}#{{ end }}memcache_pool_connection_get_timeout = {{ .Values.conf.oslo.cache.memcache_pool_connection_get_timeout | default "10" }}


[catalog]

#
# From keystone
#

# Absolute path to the file used for the templated catalog backend. This option
# is only used if the `[catalog] driver` is set to `templated`. (string value)
# from .Values.conf.keystone.template_file
{{ if not .Values.conf.keystone.template_file }}#{{ end }}template_file = {{ .Values.conf.keystone.template_file | default "default_catalog.templates" }}

# Entry point for the catalog driver in the `keystone.catalog` namespace.
# Keystone provides a `sql` option (which supports basic CRUD operations
# through SQL), a `templated` option (which loads the catalog from a templated
# catalog file on disk), and a `endpoint_filter.sql` option (which supports
# arbitrary service catalogs per project). (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Toggle for catalog caching. This has no effect unless global caching is
# enabled. In a typical deployment, there is no reason to disable this.
# (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time to cache catalog data (in seconds). This has no effect unless global and
# catalog caching are both enabled. Catalog data (services, endpoints, etc.)
# typically does not change frequently, and so a longer duration than the
# global default may be desirable. (integer value)
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "<None>" }}

# Maximum number of entities that will be returned in a catalog collection.
# There is typically no reason to set this, as it would be unusual for a
# deployment to have enough services or endpoints to exceed a reasonable limit.
# (integer value)
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}


[cors]

#
# From oslo.middleware
#

# Indicate whether this resource may be shared with the domain received in the
# requests "origin" header. Format: "<protocol>://<host>[:<port>]", no trailing
# slash. Example: https://horizon.example.com (list value)
# from .Values.conf.oslo.middleware.allowed_origin
{{ if not .Values.conf.oslo.middleware.allowed_origin }}#{{ end }}allowed_origin = {{ .Values.conf.oslo.middleware.allowed_origin | default "<None>" }}

# Indicate that the actual request can include user credentials (boolean value)
# from .Values.conf.oslo.middleware.allow_credentials
{{ if not .Values.conf.oslo.middleware.allow_credentials }}#{{ end }}allow_credentials = {{ .Values.conf.oslo.middleware.allow_credentials | default "true" }}

# Indicate which headers are safe to expose to the API. Defaults to HTTP Simple
# Headers. (list value)
# from .Values.conf.oslo.middleware.expose_headers
{{ if not .Values.conf.oslo.middleware.expose_headers }}#{{ end }}expose_headers = {{ .Values.conf.oslo.middleware.expose_headers | default "X-Auth-Token,X-Openstack-Request-Id,X-Subject-Token" }}

# Maximum cache age of CORS preflight requests. (integer value)
# from .Values.conf.oslo.middleware.max_age
{{ if not .Values.conf.oslo.middleware.max_age }}#{{ end }}max_age = {{ .Values.conf.oslo.middleware.max_age | default "3600" }}

# Indicate which methods can be used during the actual request. (list value)
# from .Values.conf.oslo.middleware.allow_methods
{{ if not .Values.conf.oslo.middleware.allow_methods }}#{{ end }}allow_methods = {{ .Values.conf.oslo.middleware.allow_methods | default "GET,PUT,POST,DELETE,PATCH" }}

# Indicate which header field names may be used during the actual request.
# (list value)
# from .Values.conf.oslo.middleware.allow_headers
{{ if not .Values.conf.oslo.middleware.allow_headers }}#{{ end }}allow_headers = {{ .Values.conf.oslo.middleware.allow_headers | default "X-Auth-Token,X-Openstack-Request-Id,X-Subject-Token,X-Project-Id,X-Project-Name,X-Project-Domain-Id,X-Project-Domain-Name,X-Domain-Id,X-Domain-Name" }}


[cors.subdomain]

#
# From oslo.middleware
#

# Indicate whether this resource may be shared with the domain received in the
# requests "origin" header. Format: "<protocol>://<host>[:<port>]", no trailing
# slash. Example: https://horizon.example.com (list value)
# from .Values.conf.oslo.middleware.allowed_origin
{{ if not .Values.conf.oslo.middleware.allowed_origin }}#{{ end }}allowed_origin = {{ .Values.conf.oslo.middleware.allowed_origin | default "<None>" }}

# Indicate that the actual request can include user credentials (boolean value)
# from .Values.conf.oslo.middleware.allow_credentials
{{ if not .Values.conf.oslo.middleware.allow_credentials }}#{{ end }}allow_credentials = {{ .Values.conf.oslo.middleware.allow_credentials | default "true" }}

# Indicate which headers are safe to expose to the API. Defaults to HTTP Simple
# Headers. (list value)
# from .Values.conf.oslo.middleware.expose_headers
{{ if not .Values.conf.oslo.middleware.expose_headers }}#{{ end }}expose_headers = {{ .Values.conf.oslo.middleware.expose_headers | default "X-Auth-Token,X-Openstack-Request-Id,X-Subject-Token" }}

# Maximum cache age of CORS preflight requests. (integer value)
# from .Values.conf.oslo.middleware.max_age
{{ if not .Values.conf.oslo.middleware.max_age }}#{{ end }}max_age = {{ .Values.conf.oslo.middleware.max_age | default "3600" }}

# Indicate which methods can be used during the actual request. (list value)
# from .Values.conf.oslo.middleware.allow_methods
{{ if not .Values.conf.oslo.middleware.allow_methods }}#{{ end }}allow_methods = {{ .Values.conf.oslo.middleware.allow_methods | default "GET,PUT,POST,DELETE,PATCH" }}

# Indicate which header field names may be used during the actual request.
# (list value)
# from .Values.conf.oslo.middleware.allow_headers
{{ if not .Values.conf.oslo.middleware.allow_headers }}#{{ end }}allow_headers = {{ .Values.conf.oslo.middleware.allow_headers | default "X-Auth-Token,X-Openstack-Request-Id,X-Subject-Token,X-Project-Id,X-Project-Name,X-Project-Domain-Id,X-Project-Domain-Name,X-Domain-Id,X-Domain-Name" }}


[credential]

#
# From keystone
#

# Entry point for the credential backend driver in the `keystone.credential`
# namespace. Keystone only provides a `sql` driver, so there's no reason to
# change this unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Entry point for credential encryption and decryption operations in the
# `keystone.credential.provider` namespace. Keystone only provides a `fernet`
# driver, so there's no reason to change this unless you are providing a custom
# entry point to encrypt and decrypt credentials. (string value)
# from .Values.conf.keystone.provider
{{ if not .Values.conf.keystone.provider }}#{{ end }}provider = {{ .Values.conf.keystone.provider | default "fernet" }}

# Directory containing Fernet keys used to encrypt and decrypt credentials
# stored in the credential backend. Fernet keys used to encrypt credentials
# have no relationship to Fernet keys used to encrypt Fernet tokens. Both sets
# of keys should be managed separately and require different rotation policies.
# Do not share this repository with the repository used to manage keys for
# Fernet tokens. (string value)
# from .Values.conf.keystone.key_repository
{{ if not .Values.conf.keystone.key_repository }}#{{ end }}key_repository = {{ .Values.conf.keystone.key_repository | default "/etc/keystone/credential-keys/" }}


[database]

#
# From oslo.db
#

# DEPRECATED: The file name to use with SQLite. (string value)
# Deprecated group/name - [DEFAULT]/sqlite_db
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Should use config option connection or slave_connection to connect
# the database.
# from .Values.conf.oslo.db.sqlite_db
{{ if not .Values.conf.oslo.db.sqlite_db }}#{{ end }}sqlite_db = {{ .Values.conf.oslo.db.sqlite_db | default "oslo.sqlite" }}

# If True, SQLite uses synchronous mode. (boolean value)
# Deprecated group/name - [DEFAULT]/sqlite_synchronous
# from .Values.conf.oslo.db.sqlite_synchronous
{{ if not .Values.conf.oslo.db.sqlite_synchronous }}#{{ end }}sqlite_synchronous = {{ .Values.conf.oslo.db.sqlite_synchronous | default "true" }}

# The back end to use for the database. (string value)
# Deprecated group/name - [DEFAULT]/db_backend
# from .Values.conf.oslo.db.backend
{{ if not .Values.conf.oslo.db.backend }}#{{ end }}backend = {{ .Values.conf.oslo.db.backend | default "sqlalchemy" }}

# The SQLAlchemy connection string to use to connect to the database. (string
# value)
# Deprecated group/name - [DEFAULT]/sql_connection
# Deprecated group/name - [DATABASE]/sql_connection
# Deprecated group/name - [sql]/connection
# from .Values.conf.oslo.db.connection
{{ if not .Values.conf.oslo.db.connection }}#{{ end }}connection = {{ .Values.conf.oslo.db.connection | default "<None>" }}

# The SQLAlchemy connection string to use to connect to the slave database.
# (string value)
# from .Values.conf.oslo.db.slave_connection
{{ if not .Values.conf.oslo.db.slave_connection }}#{{ end }}slave_connection = {{ .Values.conf.oslo.db.slave_connection | default "<None>" }}

# The SQL mode to be used for MySQL sessions. This option, including the
# default, overrides any server-set SQL mode. To use whatever SQL mode is set
# by the server configuration, set this to no value. Example: mysql_sql_mode=
# (string value)
# from .Values.conf.oslo.db.mysql_sql_mode
{{ if not .Values.conf.oslo.db.mysql_sql_mode }}#{{ end }}mysql_sql_mode = {{ .Values.conf.oslo.db.mysql_sql_mode | default "TRADITIONAL" }}

# Timeout before idle SQL connections are reaped. (integer value)
# Deprecated group/name - [DEFAULT]/sql_idle_timeout
# Deprecated group/name - [DATABASE]/sql_idle_timeout
# Deprecated group/name - [sql]/idle_timeout
# from .Values.conf.oslo.db.idle_timeout
{{ if not .Values.conf.oslo.db.idle_timeout }}#{{ end }}idle_timeout = {{ .Values.conf.oslo.db.idle_timeout | default "3600" }}

# Minimum number of SQL connections to keep open in a pool. (integer value)
# Deprecated group/name - [DEFAULT]/sql_min_pool_size
# Deprecated group/name - [DATABASE]/sql_min_pool_size
# from .Values.conf.oslo.db.min_pool_size
{{ if not .Values.conf.oslo.db.min_pool_size }}#{{ end }}min_pool_size = {{ .Values.conf.oslo.db.min_pool_size | default "1" }}

# Maximum number of SQL connections to keep open in a pool. Setting a value of
# 0 indicates no limit. (integer value)
# Deprecated group/name - [DEFAULT]/sql_max_pool_size
# Deprecated group/name - [DATABASE]/sql_max_pool_size
# from .Values.conf.oslo.db.max_pool_size
{{ if not .Values.conf.oslo.db.max_pool_size }}#{{ end }}max_pool_size = {{ .Values.conf.oslo.db.max_pool_size | default "5" }}

# Maximum number of database connection retries during startup. Set to -1 to
# specify an infinite retry count. (integer value)
# Deprecated group/name - [DEFAULT]/sql_max_retries
# Deprecated group/name - [DATABASE]/sql_max_retries
# from .Values.conf.oslo.db.max_retries
{{ if not .Values.conf.oslo.db.max_retries }}#{{ end }}max_retries = {{ .Values.conf.oslo.db.max_retries | default "10" }}

# Interval between retries of opening a SQL connection. (integer value)
# Deprecated group/name - [DEFAULT]/sql_retry_interval
# Deprecated group/name - [DATABASE]/reconnect_interval
# from .Values.conf.oslo.db.retry_interval
{{ if not .Values.conf.oslo.db.retry_interval }}#{{ end }}retry_interval = {{ .Values.conf.oslo.db.retry_interval | default "10" }}

# If set, use this value for max_overflow with SQLAlchemy. (integer value)
# Deprecated group/name - [DEFAULT]/sql_max_overflow
# Deprecated group/name - [DATABASE]/sqlalchemy_max_overflow
# from .Values.conf.oslo.db.max_overflow
{{ if not .Values.conf.oslo.db.max_overflow }}#{{ end }}max_overflow = {{ .Values.conf.oslo.db.max_overflow | default "50" }}

# Verbosity of SQL debugging information: 0=None, 100=Everything. (integer
# value)
# Minimum value: 0
# Maximum value: 100
# Deprecated group/name - [DEFAULT]/sql_connection_debug
# from .Values.conf.oslo.db.connection_debug
{{ if not .Values.conf.oslo.db.connection_debug }}#{{ end }}connection_debug = {{ .Values.conf.oslo.db.connection_debug | default "0" }}

# Add Python stack traces to SQL as comment strings. (boolean value)
# Deprecated group/name - [DEFAULT]/sql_connection_trace
# from .Values.conf.oslo.db.connection_trace
{{ if not .Values.conf.oslo.db.connection_trace }}#{{ end }}connection_trace = {{ .Values.conf.oslo.db.connection_trace | default "false" }}

# If set, use this value for pool_timeout with SQLAlchemy. (integer value)
# Deprecated group/name - [DATABASE]/sqlalchemy_pool_timeout
# from .Values.conf.oslo.db.pool_timeout
{{ if not .Values.conf.oslo.db.pool_timeout }}#{{ end }}pool_timeout = {{ .Values.conf.oslo.db.pool_timeout | default "<None>" }}

# Enable the experimental use of database reconnect on connection lost.
# (boolean value)
# from .Values.conf.oslo.db.use_db_reconnect
{{ if not .Values.conf.oslo.db.use_db_reconnect }}#{{ end }}use_db_reconnect = {{ .Values.conf.oslo.db.use_db_reconnect | default "false" }}

# Seconds between retries of a database transaction. (integer value)
# from .Values.conf.oslo.db.db_retry_interval
{{ if not .Values.conf.oslo.db.db_retry_interval }}#{{ end }}db_retry_interval = {{ .Values.conf.oslo.db.db_retry_interval | default "1" }}

# If True, increases the interval between retries of a database operation up to
# db_max_retry_interval. (boolean value)
# from .Values.conf.oslo.db.db_inc_retry_interval
{{ if not .Values.conf.oslo.db.db_inc_retry_interval }}#{{ end }}db_inc_retry_interval = {{ .Values.conf.oslo.db.db_inc_retry_interval | default "true" }}

# If db_inc_retry_interval is set, the maximum seconds between retries of a
# database operation. (integer value)
# from .Values.conf.oslo.db.db_max_retry_interval
{{ if not .Values.conf.oslo.db.db_max_retry_interval }}#{{ end }}db_max_retry_interval = {{ .Values.conf.oslo.db.db_max_retry_interval | default "10" }}

# Maximum retries in case of connection error or deadlock error before error is
# raised. Set to -1 to specify an infinite retry count. (integer value)
# from .Values.conf.oslo.db.db_max_retries
{{ if not .Values.conf.oslo.db.db_max_retries }}#{{ end }}db_max_retries = {{ .Values.conf.oslo.db.db_max_retries | default "20" }}


[domain_config]

#
# From keystone
#

# Entry point for the domain-specific configuration driver in the
# `keystone.resource.domain_config` namespace. Only a `sql` option is provided
# by keystone, so there is no reason to set this unless you are providing a
# custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Toggle for caching of the domain-specific configuration backend. This has no
# effect unless global caching is enabled. There is normally no reason to
# disable this. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time-to-live (TTL, in seconds) to cache domain-specific configuration data.
# This has no effect unless `[domain_config] caching` is enabled. (integer
# value)
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "300" }}


[endpoint_filter]

#
# From keystone
#

# Entry point for the endpoint filter driver in the `keystone.endpoint_filter`
# namespace. Only a `sql` option is provided by keystone, so there is no reason
# to set this unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# This controls keystone's behavior if the configured endpoint filters do not
# result in any endpoints for a user + project pair (and therefore a
# potentially empty service catalog). If set to true, keystone will return the
# entire service catalog. If set to false, keystone will return an empty
# service catalog. (boolean value)
# from .Values.conf.keystone.return_all_endpoints_if_no_filter
{{ if not .Values.conf.keystone.return_all_endpoints_if_no_filter }}#{{ end }}return_all_endpoints_if_no_filter = {{ .Values.conf.keystone.return_all_endpoints_if_no_filter | default "true" }}


[endpoint_policy]

#
# From keystone
#

# Entry point for the endpoint policy driver in the `keystone.endpoint_policy`
# namespace. Only a `sql` driver is provided by keystone, so there is no reason
# to set this unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}


[eventlet_server]

#
# From keystone
#

# DEPRECATED: The IP address of the network interface for the public service to
# listen on. (string value)
# Deprecated group/name - [DEFAULT]/bind_host
# Deprecated group/name - [DEFAULT]/public_bind_host
# This option is deprecated for removal since K.
# Its value may be silently ignored in the future.
# Reason: Support for running keystone under eventlet has been removed in the
# Newton release. These options remain for backwards compatibility because they
# are used for URL substitutions.
# from .Values.conf.keystone.public_bind_host
{{ if not .Values.conf.keystone.public_bind_host }}#{{ end }}public_bind_host = {{ .Values.conf.keystone.public_bind_host | default "0.0.0.0" }}

# DEPRECATED: The port number for the public service to listen on. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/public_port
# This option is deprecated for removal since K.
# Its value may be silently ignored in the future.
# Reason: Support for running keystone under eventlet has been removed in the
# Newton release. These options remain for backwards compatibility because they
# are used for URL substitutions.
# from .Values.conf.keystone.public_port
{{ if not .Values.conf.keystone.public_port }}#{{ end }}public_port = {{ .Values.conf.keystone.public_port | default "5000" }}

# DEPRECATED: The IP address of the network interface for the admin service to
# listen on. (string value)
# Deprecated group/name - [DEFAULT]/bind_host
# Deprecated group/name - [DEFAULT]/admin_bind_host
# This option is deprecated for removal since K.
# Its value may be silently ignored in the future.
# Reason: Support for running keystone under eventlet has been removed in the
# Newton release. These options remain for backwards compatibility because they
# are used for URL substitutions.
# from .Values.conf.keystone.admin_bind_host
{{ if not .Values.conf.keystone.admin_bind_host }}#{{ end }}admin_bind_host = {{ .Values.conf.keystone.admin_bind_host | default "0.0.0.0" }}

# DEPRECATED: The port number for the admin service to listen on. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/admin_port
# This option is deprecated for removal since K.
# Its value may be silently ignored in the future.
# Reason: Support for running keystone under eventlet has been removed in the
# Newton release. These options remain for backwards compatibility because they
# are used for URL substitutions.
# from .Values.conf.keystone.admin_port
{{ if not .Values.conf.keystone.admin_port }}#{{ end }}admin_port = {{ .Values.conf.keystone.admin_port | default "35357" }}


[federation]

#
# From keystone
#

# Entry point for the federation backend driver in the `keystone.federation`
# namespace. Keystone only provides a `sql` driver, so there is no reason to
# set this option unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Prefix to use when filtering environment variable names for federated
# assertions. Matched variables are passed into the federated mapping engine.
# (string value)
# from .Values.conf.keystone.assertion_prefix
{{ if not .Values.conf.keystone.assertion_prefix }}#{{ end }}assertion_prefix = {{ .Values.conf.keystone.assertion_prefix | default "" }}

# Value to be used to obtain the entity ID of the Identity Provider from the
# environment. For `mod_shib`, this would be `Shib-Identity-Provider`. For For
# `mod_auth_openidc`, this could be `HTTP_OIDC_ISS`. For `mod_auth_mellon`,
# this could be `MELLON_IDP`. (string value)
# from .Values.conf.keystone.remote_id_attribute
{{ if not .Values.conf.keystone.remote_id_attribute }}#{{ end }}remote_id_attribute = {{ .Values.conf.keystone.remote_id_attribute | default "<None>" }}

# An arbitrary domain name that is reserved to allow federated ephemeral users
# to have a domain concept. Note that an admin will not be able to create a
# domain with this name or update an existing domain to this name. You are not
# advised to change this value unless you really have to. (string value)
# from .Values.conf.keystone.federated_domain_name
{{ if not .Values.conf.keystone.federated_domain_name }}#{{ end }}federated_domain_name = {{ .Values.conf.keystone.federated_domain_name | default "Federated" }}

# A list of trusted dashboard hosts. Before accepting a Single Sign-On request
# to return a token, the origin host must be a member of this list. This
# configuration option may be repeated for multiple values. You must set this
# in order to use web-based SSO flows. For example:
# trusted_dashboard=https://acme.example.com/auth/websso
# trusted_dashboard=https://beta.example.com/auth/websso (multi valued)
# from .Values.conf.keystone.trusted_dashboard
{{ if not .Values.conf.keystone.trusted_dashboard }}#{{ end }}trusted_dashboard = {{ .Values.conf.keystone.trusted_dashboard | default "" }}

# Absolute path to an HTML file used as a Single Sign-On callback handler. This
# page is expected to redirect the user from keystone back to a trusted
# dashboard host, by form encoding a token in a POST request. Keystone's
# default value should be sufficient for most deployments. (string value)
# from .Values.conf.keystone.sso_callback_template
{{ if not .Values.conf.keystone.sso_callback_template }}#{{ end }}sso_callback_template = {{ .Values.conf.keystone.sso_callback_template | default "/etc/keystone/sso_callback_template.html" }}

# Toggle for federation caching. This has no effect unless global caching is
# enabled. There is typically no reason to disable this. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}


[fernet_tokens]

#
# From keystone
#

# Directory containing Fernet token keys. This directory must exist before
# using `keystone-manage fernet_setup` for the first time, must be writable by
# the user running `keystone-manage fernet_setup` or `keystone-manage
# fernet_rotate`, and of course must be readable by keystone's server process.
# The repository may contain keys in one of three states: a single staged key
# (always index 0) used for token validation, a single primary key (always the
# highest index) used for token creation and validation, and any number of
# secondary keys (all other index values) used for token validation. With
# multiple keystone nodes, each node must share the same key repository
# contents, with the exception of the staged key (index 0). It is safe to run
# `keystone-manage fernet_rotate` once on any one node to promote a staged key
# (index 0) to be the new primary (incremented from the previous highest
# index), and produce a new staged key (a new key with index 0); the resulting
# repository can then be atomically replicated to other nodes without any risk
# of race conditions (for example, it is safe to run `keystone-manage
# fernet_rotate` on host A, wait any amount of time, create a tarball of the
# directory on host A, unpack it on host B to a temporary location, and
# atomically move (`mv`) the directory into place on host B). Running
# `keystone-manage fernet_rotate` *twice* on a key repository without syncing
# other nodes will result in tokens that can not be validated by all nodes.
# (string value)
# from .Values.conf.keystone.key_repository
{{ if not .Values.conf.keystone.key_repository }}#{{ end }}key_repository = {{ .Values.conf.keystone.key_repository | default "/etc/keystone/fernet-keys/" }}

# This controls how many keys are held in rotation by `keystone-manage
# fernet_rotate` before they are discarded. The default value of 3 means that
# keystone will maintain one staged key (always index 0), one primary key (the
# highest numerical index), and one secondary key (every other index).
# Increasing this value means that additional secondary keys will be kept in
# the rotation. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.max_active_keys
{{ if not .Values.conf.keystone.max_active_keys }}#{{ end }}max_active_keys = {{ .Values.conf.keystone.max_active_keys | default "3" }}


[healthcheck]

#
# From oslo.middleware
#

# DEPRECATED: The path to respond to healtcheck requests on. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .Values.conf.oslo.middleware.path
{{ if not .Values.conf.oslo.middleware.path }}#{{ end }}path = {{ .Values.conf.oslo.middleware.path | default "/healthcheck" }}

# Show more detailed information as part of the response (boolean value)
# from .Values.conf.oslo.middleware.detailed
{{ if not .Values.conf.oslo.middleware.detailed }}#{{ end }}detailed = {{ .Values.conf.oslo.middleware.detailed | default "false" }}

# Additional backends that can perform health checks and report that
# information back as part of a request. (list value)
# from .Values.conf.oslo.middleware.backends
{{ if not .Values.conf.oslo.middleware.backends }}#{{ end }}backends = {{ .Values.conf.oslo.middleware.backends | default "" }}

# Check the presence of a file to determine if an application is running on a
# port. Used by DisableByFileHealthcheck plugin. (string value)
# from .Values.conf.oslo.middleware.disable_by_file_path
{{ if not .Values.conf.oslo.middleware.disable_by_file_path }}#{{ end }}disable_by_file_path = {{ .Values.conf.oslo.middleware.disable_by_file_path | default "<None>" }}

# Check the presence of a file based on a port to determine if an application
# is running on a port. Expects a "port:path" list of strings. Used by
# DisableByFilesPortsHealthcheck plugin. (list value)
# from .Values.conf.oslo.middleware.disable_by_file_paths
{{ if not .Values.conf.oslo.middleware.disable_by_file_paths }}#{{ end }}disable_by_file_paths = {{ .Values.conf.oslo.middleware.disable_by_file_paths | default "" }}


[identity]

#
# From keystone
#

# This references the domain to use for all Identity API v2 requests (which are
# not aware of domains). A domain with this ID can optionally be created for
# you by `keystone-manage bootstrap`. The domain referenced by this ID cannot
# be deleted on the v3 API, to prevent accidentally breaking the v2 API. There
# is nothing special about this domain, other than the fact that it must exist
# to order to maintain support for your v2 clients. There is typically no
# reason to change this value. (string value)
# from .Values.conf.keystone.default_domain_id
{{ if not .Values.conf.keystone.default_domain_id }}#{{ end }}default_domain_id = {{ .Values.conf.keystone.default_domain_id | default "default" }}

# A subset (or all) of domains can have their own identity driver, each with
# their own partial configuration options, stored in either the resource
# backend or in a file in a domain configuration directory (depending on the
# setting of `[identity] domain_configurations_from_database`). Only values
# specific to the domain need to be specified in this manner. This feature is
# disabled by default, but may be enabled by default in a future release; set
# to true to enable. (boolean value)
# from .Values.conf.keystone.domain_specific_drivers_enabled
{{ if not .Values.conf.keystone.domain_specific_drivers_enabled }}#{{ end }}domain_specific_drivers_enabled = {{ .Values.conf.keystone.domain_specific_drivers_enabled | default "false" }}

# By default, domain-specific configuration data is read from files in the
# directory identified by `[identity] domain_config_dir`. Enabling this
# configuration option allows you to instead manage domain-specific
# configurations through the API, which are then persisted in the backend
# (typically, a SQL database), rather than using configuration files on disk.
# (boolean value)
# from .Values.conf.keystone.domain_configurations_from_database
{{ if not .Values.conf.keystone.domain_configurations_from_database }}#{{ end }}domain_configurations_from_database = {{ .Values.conf.keystone.domain_configurations_from_database | default "false" }}

# Absolute path where keystone should locate domain-specific `[identity]`
# configuration files. This option has no effect unless `[identity]
# domain_specific_drivers_enabled` is set to true. There is typically no reason
# to change this value. (string value)
# from .Values.conf.keystone.domain_config_dir
{{ if not .Values.conf.keystone.domain_config_dir }}#{{ end }}domain_config_dir = {{ .Values.conf.keystone.domain_config_dir | default "/etc/keystone/domains" }}

# Entry point for the identity backend driver in the `keystone.identity`
# namespace. Keystone provides a `sql` and `ldap` driver. This option is also
# used as the default driver selection (along with the other configuration
# variables in this section) in the event that `[identity]
# domain_specific_drivers_enabled` is enabled, but no applicable domain-
# specific configuration is defined for the domain in question. Unless your
# deployment primarily relies on `ldap` AND is not using domain-specific
# configuration, you should typically leave this set to `sql`. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Toggle for identity caching. This has no effect unless global caching is
# enabled. There is typically no reason to disable this. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time to cache identity data (in seconds). This has no effect unless global
# and identity caching are enabled. (integer value)
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "600" }}

# Maximum allowed length for user passwords. Decrease this value to improve
# performance. Changing this value does not effect existing passwords. (integer
# value)
# Maximum value: 4096
# from .Values.conf.keystone.max_password_length
{{ if not .Values.conf.keystone.max_password_length }}#{{ end }}max_password_length = {{ .Values.conf.keystone.max_password_length | default "4096" }}

# Maximum number of entities that will be returned in an identity collection.
# (integer value)
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}


[identity_mapping]

#
# From keystone
#

# Entry point for the identity mapping backend driver in the
# `keystone.identity.id_mapping` namespace. Keystone only provides a `sql`
# driver, so there is no reason to change this unless you are providing a
# custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Entry point for the public ID generator for user and group entities in the
# `keystone.identity.id_generator` namespace. The Keystone identity mapper only
# supports generators that produce 64 bytes or less. Keystone only provides a
# `sha256` entry point, so there is no reason to change this value unless
# you're providing a custom entry point. (string value)
# from .Values.conf.keystone.generator
{{ if not .Values.conf.keystone.generator }}#{{ end }}generator = {{ .Values.conf.keystone.generator | default "sha256" }}

# The format of user and group IDs changed in Juno for backends that do not
# generate UUIDs (for example, LDAP), with keystone providing a hash mapping to
# the underlying attribute in LDAP. By default this mapping is disabled, which
# ensures that existing IDs will not change. Even when the mapping is enabled
# by using domain-specific drivers (`[identity]
# domain_specific_drivers_enabled`), any users and groups from the default
# domain being handled by LDAP will still not be mapped to ensure their IDs
# remain backward compatible. Setting this value to false will enable the new
# mapping for all backends, including the default LDAP driver. It is only
# guaranteed to be safe to enable this option if you do not already have
# assignments for users and groups from the default LDAP domain, and you
# consider it to be acceptable for Keystone to provide the different IDs to
# clients than it did previously (existing IDs in the API will suddenly
# change). Typically this means that the only time you can set this value to
# false is when configuring a fresh installation, although that is the
# recommended value. (boolean value)
# from .Values.conf.keystone.backward_compatible_ids
{{ if not .Values.conf.keystone.backward_compatible_ids }}#{{ end }}backward_compatible_ids = {{ .Values.conf.keystone.backward_compatible_ids | default "true" }}


[ldap]

#
# From keystone
#

# URL(s) for connecting to the LDAP server. Multiple LDAP URLs may be specified
# as a comma separated string. The first URL to successfully bind is used for
# the connection. (string value)
# from .Values.conf.keystone.url
{{ if not .Values.conf.keystone.url }}#{{ end }}url = {{ .Values.conf.keystone.url | default "ldap://localhost" }}

# The user name of the administrator bind DN to use when querying the LDAP
# server, if your LDAP server requires it. (string value)
# from .Values.conf.keystone.user
{{ if not .Values.conf.keystone.user }}#{{ end }}user = {{ .Values.conf.keystone.user | default "<None>" }}

# The password of the administrator bind DN to use when querying the LDAP
# server, if your LDAP server requires it. (string value)
# from .Values.conf.keystone.password
{{ if not .Values.conf.keystone.password }}#{{ end }}password = {{ .Values.conf.keystone.password | default "<None>" }}

# The default LDAP server suffix to use, if a DN is not defined via either
# `[ldap] user_tree_dn` or `[ldap] group_tree_dn`. (string value)
# from .Values.conf.keystone.suffix
{{ if not .Values.conf.keystone.suffix }}#{{ end }}suffix = {{ .Values.conf.keystone.suffix | default "cn=example,cn=com" }}

# The search scope which defines how deep to search within the search base. A
# value of `one` (representing `oneLevel` or `singleLevel`) indicates a search
# of objects immediately below to the base object, but does not include the
# base object itself. A value of `sub` (representing `subtree` or
# `wholeSubtree`) indicates a search of both the base object itself and the
# entire subtree below it. (string value)
# Allowed values: one, sub
# from .Values.conf.keystone.query_scope
{{ if not .Values.conf.keystone.query_scope }}#{{ end }}query_scope = {{ .Values.conf.keystone.query_scope | default "one" }}

# Defines the maximum number of results per page that keystone should request
# from the LDAP server when listing objects. A value of zero (`0`) disables
# paging. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.page_size
{{ if not .Values.conf.keystone.page_size }}#{{ end }}page_size = {{ .Values.conf.keystone.page_size | default "0" }}

# The LDAP dereferencing option to use for queries involving aliases. A value
# of `default` falls back to using default dereferencing behavior configured by
# your `ldap.conf`. A value of `never` prevents aliases from being dereferenced
# at all. A value of `searching` dereferences aliases only after name
# resolution. A value of `finding` dereferences aliases only during name
# resolution. A value of `always` dereferences aliases in all cases. (string
# value)
# Allowed values: never, searching, always, finding, default
# from .Values.conf.keystone.alias_dereferencing
{{ if not .Values.conf.keystone.alias_dereferencing }}#{{ end }}alias_dereferencing = {{ .Values.conf.keystone.alias_dereferencing | default "default" }}

# Sets the LDAP debugging level for LDAP calls. A value of 0 means that
# debugging is not enabled. This value is a bitmask, consult your LDAP
# documentation for possible values. (integer value)
# Minimum value: -1
# from .Values.conf.keystone.debug_level
{{ if not .Values.conf.keystone.debug_level }}#{{ end }}debug_level = {{ .Values.conf.keystone.debug_level | default "<None>" }}

# Sets keystone's referral chasing behavior across directory partitions. If
# left unset, the system's default behavior will be used. (boolean value)
# from .Values.conf.keystone.chase_referrals
{{ if not .Values.conf.keystone.chase_referrals }}#{{ end }}chase_referrals = {{ .Values.conf.keystone.chase_referrals | default "<None>" }}

# The search base to use for users. Defaults to the `[ldap] suffix` value.
# (string value)
# from .Values.conf.keystone.user_tree_dn
{{ if not .Values.conf.keystone.user_tree_dn }}#{{ end }}user_tree_dn = {{ .Values.conf.keystone.user_tree_dn | default "<None>" }}

# The LDAP search filter to use for users. (string value)
# from .Values.conf.keystone.user_filter
{{ if not .Values.conf.keystone.user_filter }}#{{ end }}user_filter = {{ .Values.conf.keystone.user_filter | default "<None>" }}

# The LDAP object class to use for users. (string value)
# from .Values.conf.keystone.user_objectclass
{{ if not .Values.conf.keystone.user_objectclass }}#{{ end }}user_objectclass = {{ .Values.conf.keystone.user_objectclass | default "inetOrgPerson" }}

# The LDAP attribute mapped to user IDs in keystone. This must NOT be a
# multivalued attribute. User IDs are expected to be globally unique across
# keystone domains and URL-safe. (string value)
# from .Values.conf.keystone.user_id_attribute
{{ if not .Values.conf.keystone.user_id_attribute }}#{{ end }}user_id_attribute = {{ .Values.conf.keystone.user_id_attribute | default "cn" }}

# The LDAP attribute mapped to user names in keystone. User names are expected
# to be unique only within a keystone domain and are not expected to be URL-
# safe. (string value)
# from .Values.conf.keystone.user_name_attribute
{{ if not .Values.conf.keystone.user_name_attribute }}#{{ end }}user_name_attribute = {{ .Values.conf.keystone.user_name_attribute | default "sn" }}

# The LDAP attribute mapped to user descriptions in keystone. (string value)
# from .Values.conf.keystone.user_description_attribute
{{ if not .Values.conf.keystone.user_description_attribute }}#{{ end }}user_description_attribute = {{ .Values.conf.keystone.user_description_attribute | default "description" }}

# The LDAP attribute mapped to user emails in keystone. (string value)
# from .Values.conf.keystone.user_mail_attribute
{{ if not .Values.conf.keystone.user_mail_attribute }}#{{ end }}user_mail_attribute = {{ .Values.conf.keystone.user_mail_attribute | default "mail" }}

# The LDAP attribute mapped to user passwords in keystone. (string value)
# from .Values.conf.keystone.user_pass_attribute
{{ if not .Values.conf.keystone.user_pass_attribute }}#{{ end }}user_pass_attribute = {{ .Values.conf.keystone.user_pass_attribute | default "userPassword" }}

# The LDAP attribute mapped to the user enabled attribute in keystone. If
# setting this option to `userAccountControl`, then you may be interested in
# setting `[ldap] user_enabled_mask` and `[ldap] user_enabled_default` as well.
# (string value)
# from .Values.conf.keystone.user_enabled_attribute
{{ if not .Values.conf.keystone.user_enabled_attribute }}#{{ end }}user_enabled_attribute = {{ .Values.conf.keystone.user_enabled_attribute | default "enabled" }}

# Logically negate the boolean value of the enabled attribute obtained from the
# LDAP server. Some LDAP servers use a boolean lock attribute where "true"
# means an account is disabled. Setting `[ldap] user_enabled_invert = true`
# will allow these lock attributes to be used. This option will have no effect
# if either the `[ldap] user_enabled_mask` or `[ldap] user_enabled_emulation`
# options are in use. (boolean value)
# from .Values.conf.keystone.user_enabled_invert
{{ if not .Values.conf.keystone.user_enabled_invert }}#{{ end }}user_enabled_invert = {{ .Values.conf.keystone.user_enabled_invert | default "false" }}

# Bitmask integer to select which bit indicates the enabled value if the LDAP
# server represents "enabled" as a bit on an integer rather than as a discrete
# boolean. A value of `0` indicates that the mask is not used. If this is not
# set to `0` the typical value is `2`. This is typically used when `[ldap]
# user_enabled_attribute = userAccountControl`. Setting this option causes
# keystone to ignore the value of `[ldap] user_enabled_invert`. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.user_enabled_mask
{{ if not .Values.conf.keystone.user_enabled_mask }}#{{ end }}user_enabled_mask = {{ .Values.conf.keystone.user_enabled_mask | default "0" }}

# The default value to enable users. This should match an appropriate integer
# value if the LDAP server uses non-boolean (bitmask) values to indicate if a
# user is enabled or disabled. If this is not set to `True`, then the typical
# value is `512`. This is typically used when `[ldap] user_enabled_attribute =
# userAccountControl`. (string value)
# from .Values.conf.keystone.user_enabled_default
{{ if not .Values.conf.keystone.user_enabled_default }}#{{ end }}user_enabled_default = {{ .Values.conf.keystone.user_enabled_default | default "True" }}

# List of user attributes to ignore on create and update, or whether a specific
# user attribute should be filtered for list or show user. (list value)
# from .Values.conf.keystone.user_attribute_ignore
{{ if not .Values.conf.keystone.user_attribute_ignore }}#{{ end }}user_attribute_ignore = {{ .Values.conf.keystone.user_attribute_ignore | default "default_project_id" }}

# The LDAP attribute mapped to a user's default_project_id in keystone. This is
# most commonly used when keystone has write access to LDAP. (string value)
# from .Values.conf.keystone.user_default_project_id_attribute
{{ if not .Values.conf.keystone.user_default_project_id_attribute }}#{{ end }}user_default_project_id_attribute = {{ .Values.conf.keystone.user_default_project_id_attribute | default "<None>" }}

# If enabled, keystone uses an alternative method to determine if a user is
# enabled or not by checking if they are a member of the group defined by the
# `[ldap] user_enabled_emulation_dn` option. Enabling this option causes
# keystone to ignore the value of `[ldap] user_enabled_invert`. (boolean value)
# from .Values.conf.keystone.user_enabled_emulation
{{ if not .Values.conf.keystone.user_enabled_emulation }}#{{ end }}user_enabled_emulation = {{ .Values.conf.keystone.user_enabled_emulation | default "false" }}

# DN of the group entry to hold enabled users when using enabled emulation.
# Setting this option has no effect unless `[ldap] user_enabled_emulation` is
# also enabled. (string value)
# from .Values.conf.keystone.user_enabled_emulation_dn
{{ if not .Values.conf.keystone.user_enabled_emulation_dn }}#{{ end }}user_enabled_emulation_dn = {{ .Values.conf.keystone.user_enabled_emulation_dn | default "<None>" }}

# Use the `[ldap] group_member_attribute` and `[ldap] group_objectclass`
# settings to determine membership in the emulated enabled group. Enabling this
# option has no effect unless `[ldap] user_enabled_emulation` is also enabled.
# (boolean value)
# from .Values.conf.keystone.user_enabled_emulation_use_group_config
{{ if not .Values.conf.keystone.user_enabled_emulation_use_group_config }}#{{ end }}user_enabled_emulation_use_group_config = {{ .Values.conf.keystone.user_enabled_emulation_use_group_config | default "false" }}

# A list of LDAP attribute to keystone user attribute pairs used for mapping
# additional attributes to users in keystone. The expected format is
# `<ldap_attr>:<user_attr>`, where `ldap_attr` is the attribute in the LDAP
# object and `user_attr` is the attribute which should appear in the identity
# API. (list value)
# from .Values.conf.keystone.user_additional_attribute_mapping
{{ if not .Values.conf.keystone.user_additional_attribute_mapping }}#{{ end }}user_additional_attribute_mapping = {{ .Values.conf.keystone.user_additional_attribute_mapping | default "" }}

# The search base to use for groups. Defaults to the `[ldap] suffix` value.
# (string value)
# from .Values.conf.keystone.group_tree_dn
{{ if not .Values.conf.keystone.group_tree_dn }}#{{ end }}group_tree_dn = {{ .Values.conf.keystone.group_tree_dn | default "<None>" }}

# The LDAP search filter to use for groups. (string value)
# from .Values.conf.keystone.group_filter
{{ if not .Values.conf.keystone.group_filter }}#{{ end }}group_filter = {{ .Values.conf.keystone.group_filter | default "<None>" }}

# The LDAP object class to use for groups. If setting this option to
# `posixGroup`, you may also be interested in enabling the `[ldap]
# group_members_are_ids` option. (string value)
# from .Values.conf.keystone.group_objectclass
{{ if not .Values.conf.keystone.group_objectclass }}#{{ end }}group_objectclass = {{ .Values.conf.keystone.group_objectclass | default "groupOfNames" }}

# The LDAP attribute mapped to group IDs in keystone. This must NOT be a
# multivalued attribute. Group IDs are expected to be globally unique across
# keystone domains and URL-safe. (string value)
# from .Values.conf.keystone.group_id_attribute
{{ if not .Values.conf.keystone.group_id_attribute }}#{{ end }}group_id_attribute = {{ .Values.conf.keystone.group_id_attribute | default "cn" }}

# The LDAP attribute mapped to group names in keystone. Group names are
# expected to be unique only within a keystone domain and are not expected to
# be URL-safe. (string value)
# from .Values.conf.keystone.group_name_attribute
{{ if not .Values.conf.keystone.group_name_attribute }}#{{ end }}group_name_attribute = {{ .Values.conf.keystone.group_name_attribute | default "ou" }}

# The LDAP attribute used to indicate that a user is a member of the group.
# (string value)
# from .Values.conf.keystone.group_member_attribute
{{ if not .Values.conf.keystone.group_member_attribute }}#{{ end }}group_member_attribute = {{ .Values.conf.keystone.group_member_attribute | default "member" }}

# Enable this option if the members of the group object class are keystone user
# IDs rather than LDAP DNs. This is the case when using `posixGroup` as the
# group object class in Open Directory. (boolean value)
# from .Values.conf.keystone.group_members_are_ids
{{ if not .Values.conf.keystone.group_members_are_ids }}#{{ end }}group_members_are_ids = {{ .Values.conf.keystone.group_members_are_ids | default "false" }}

# The LDAP attribute mapped to group descriptions in keystone. (string value)
# from .Values.conf.keystone.group_desc_attribute
{{ if not .Values.conf.keystone.group_desc_attribute }}#{{ end }}group_desc_attribute = {{ .Values.conf.keystone.group_desc_attribute | default "description" }}

# List of group attributes to ignore on create and update. or whether a
# specific group attribute should be filtered for list or show group. (list
# value)
# from .Values.conf.keystone.group_attribute_ignore
{{ if not .Values.conf.keystone.group_attribute_ignore }}#{{ end }}group_attribute_ignore = {{ .Values.conf.keystone.group_attribute_ignore | default "" }}

# A list of LDAP attribute to keystone group attribute pairs used for mapping
# additional attributes to groups in keystone. The expected format is
# `<ldap_attr>:<group_attr>`, where `ldap_attr` is the attribute in the LDAP
# object and `group_attr` is the attribute which should appear in the identity
# API. (list value)
# from .Values.conf.keystone.group_additional_attribute_mapping
{{ if not .Values.conf.keystone.group_additional_attribute_mapping }}#{{ end }}group_additional_attribute_mapping = {{ .Values.conf.keystone.group_additional_attribute_mapping | default "" }}

# If enabled, group queries will use Active Directory specific filters for
# nested groups. (boolean value)
# from .Values.conf.keystone.group_ad_nesting
{{ if not .Values.conf.keystone.group_ad_nesting }}#{{ end }}group_ad_nesting = {{ .Values.conf.keystone.group_ad_nesting | default "false" }}

# An absolute path to a CA certificate file to use when communicating with LDAP
# servers. This option will take precedence over `[ldap] tls_cacertdir`, so
# there is no reason to set both. (string value)
# from .Values.conf.keystone.tls_cacertfile
{{ if not .Values.conf.keystone.tls_cacertfile }}#{{ end }}tls_cacertfile = {{ .Values.conf.keystone.tls_cacertfile | default "<None>" }}

# An absolute path to a CA certificate directory to use when communicating with
# LDAP servers. There is no reason to set this option if you've also set
# `[ldap] tls_cacertfile`. (string value)
# from .Values.conf.keystone.tls_cacertdir
{{ if not .Values.conf.keystone.tls_cacertdir }}#{{ end }}tls_cacertdir = {{ .Values.conf.keystone.tls_cacertdir | default "<None>" }}

# Enable TLS when communicating with LDAP servers. You should also set the
# `[ldap] tls_cacertfile` and `[ldap] tls_cacertdir` options when using this
# option. Do not set this option if you are using LDAP over SSL (LDAPS) instead
# of TLS. (boolean value)
# from .Values.conf.keystone.use_tls
{{ if not .Values.conf.keystone.use_tls }}#{{ end }}use_tls = {{ .Values.conf.keystone.use_tls | default "false" }}

# Specifies which checks to perform against client certificates on incoming TLS
# sessions. If set to `demand`, then a certificate will always be requested and
# required from the LDAP server. If set to `allow`, then a certificate will
# always be requested but not required from the LDAP server. If set to `never`,
# then a certificate will never be requested. (string value)
# Allowed values: demand, never, allow
# from .Values.conf.keystone.tls_req_cert
{{ if not .Values.conf.keystone.tls_req_cert }}#{{ end }}tls_req_cert = {{ .Values.conf.keystone.tls_req_cert | default "demand" }}

# The connection timeout to use with the LDAP server. A value of `-1` means
# that connections will never timeout. (integer value)
# Minimum value: -1
# from .Values.conf.keystone.connection_timeout
{{ if not .Values.conf.keystone.connection_timeout }}#{{ end }}connection_timeout = {{ .Values.conf.keystone.connection_timeout | default "-1" }}

# Enable LDAP connection pooling for queries to the LDAP server. There is
# typically no reason to disable this. (boolean value)
# from .Values.conf.keystone.use_pool
{{ if not .Values.conf.keystone.use_pool }}#{{ end }}use_pool = {{ .Values.conf.keystone.use_pool | default "true" }}

# The size of the LDAP connection pool. This option has no effect unless
# `[ldap] use_pool` is also enabled. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.pool_size
{{ if not .Values.conf.keystone.pool_size }}#{{ end }}pool_size = {{ .Values.conf.keystone.pool_size | default "10" }}

# The maximum number of times to attempt reconnecting to the LDAP server before
# aborting. A value of zero prevents retries. This option has no effect unless
# `[ldap] use_pool` is also enabled. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.pool_retry_max
{{ if not .Values.conf.keystone.pool_retry_max }}#{{ end }}pool_retry_max = {{ .Values.conf.keystone.pool_retry_max | default "3" }}

# The number of seconds to wait before attempting to reconnect to the LDAP
# server. This option has no effect unless `[ldap] use_pool` is also enabled.
# (floating point value)
# from .Values.conf.keystone.pool_retry_delay
{{ if not .Values.conf.keystone.pool_retry_delay }}#{{ end }}pool_retry_delay = {{ .Values.conf.keystone.pool_retry_delay | default "0.1" }}

# The connection timeout to use when pooling LDAP connections. A value of `-1`
# means that connections will never timeout. This option has no effect unless
# `[ldap] use_pool` is also enabled. (integer value)
# Minimum value: -1
# from .Values.conf.keystone.pool_connection_timeout
{{ if not .Values.conf.keystone.pool_connection_timeout }}#{{ end }}pool_connection_timeout = {{ .Values.conf.keystone.pool_connection_timeout | default "-1" }}

# The maximum connection lifetime to the LDAP server in seconds. When this
# lifetime is exceeded, the connection will be unbound and removed from the
# connection pool. This option has no effect unless `[ldap] use_pool` is also
# enabled. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.pool_connection_lifetime
{{ if not .Values.conf.keystone.pool_connection_lifetime }}#{{ end }}pool_connection_lifetime = {{ .Values.conf.keystone.pool_connection_lifetime | default "600" }}

# Enable LDAP connection pooling for end user authentication. There is
# typically no reason to disable this. (boolean value)
# from .Values.conf.keystone.use_auth_pool
{{ if not .Values.conf.keystone.use_auth_pool }}#{{ end }}use_auth_pool = {{ .Values.conf.keystone.use_auth_pool | default "true" }}

# The size of the connection pool to use for end user authentication. This
# option has no effect unless `[ldap] use_auth_pool` is also enabled. (integer
# value)
# Minimum value: 1
# from .Values.conf.keystone.auth_pool_size
{{ if not .Values.conf.keystone.auth_pool_size }}#{{ end }}auth_pool_size = {{ .Values.conf.keystone.auth_pool_size | default "100" }}

# The maximum end user authentication connection lifetime to the LDAP server in
# seconds. When this lifetime is exceeded, the connection will be unbound and
# removed from the connection pool. This option has no effect unless `[ldap]
# use_auth_pool` is also enabled. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.auth_pool_connection_lifetime
{{ if not .Values.conf.keystone.auth_pool_connection_lifetime }}#{{ end }}auth_pool_connection_lifetime = {{ .Values.conf.keystone.auth_pool_connection_lifetime | default "60" }}


[matchmaker_redis]

#
# From oslo.messaging
#

# DEPRECATED: Host to locate redis. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.host
{{ if not .Values.conf.oslo.messaging.host }}#{{ end }}host = {{ .Values.conf.oslo.messaging.host | default "127.0.0.1" }}

# DEPRECATED: Use this port to connect to redis host. (port value)
# Minimum value: 0
# Maximum value: 65535
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.port
{{ if not .Values.conf.oslo.messaging.port }}#{{ end }}port = {{ .Values.conf.oslo.messaging.port | default "6379" }}

# DEPRECATED: Password for Redis server (optional). (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.password
{{ if not .Values.conf.oslo.messaging.password }}#{{ end }}password = {{ .Values.conf.oslo.messaging.password | default "" }}

# DEPRECATED: List of Redis Sentinel hosts (fault tolerance mode), e.g.,
# [host:port, host1:port ... ] (list value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.sentinel_hosts
{{ if not .Values.conf.oslo.messaging.sentinel_hosts }}#{{ end }}sentinel_hosts = {{ .Values.conf.oslo.messaging.sentinel_hosts | default "" }}

# Redis replica set name. (string value)
# from .Values.conf.oslo.messaging.sentinel_group_name
{{ if not .Values.conf.oslo.messaging.sentinel_group_name }}#{{ end }}sentinel_group_name = {{ .Values.conf.oslo.messaging.sentinel_group_name | default "oslo-messaging-zeromq" }}

# Time in ms to wait between connection attempts. (integer value)
# from .Values.conf.oslo.messaging.wait_timeout
{{ if not .Values.conf.oslo.messaging.wait_timeout }}#{{ end }}wait_timeout = {{ .Values.conf.oslo.messaging.wait_timeout | default "2000" }}

# Time in ms to wait before the transaction is killed. (integer value)
# from .Values.conf.oslo.messaging.check_timeout
{{ if not .Values.conf.oslo.messaging.check_timeout }}#{{ end }}check_timeout = {{ .Values.conf.oslo.messaging.check_timeout | default "20000" }}

# Timeout in ms on blocking socket operations. (integer value)
# from .Values.conf.oslo.messaging.socket_timeout
{{ if not .Values.conf.oslo.messaging.socket_timeout }}#{{ end }}socket_timeout = {{ .Values.conf.oslo.messaging.socket_timeout | default "10000" }}


[memcache]

#
# From keystone
#

# Number of seconds memcached server is considered dead before it is tried
# again. This is used by the key value store system. (integer value)
# from .Values.conf.keystone.dead_retry
{{ if not .Values.conf.keystone.dead_retry }}#{{ end }}dead_retry = {{ .Values.conf.keystone.dead_retry | default "300" }}

# Timeout in seconds for every call to a server. This is used by the key value
# store system. (integer value)
# from .Values.conf.keystone.socket_timeout
{{ if not .Values.conf.keystone.socket_timeout }}#{{ end }}socket_timeout = {{ .Values.conf.keystone.socket_timeout | default "3" }}

# Max total number of open connections to every memcached server. This is used
# by the key value store system. (integer value)
# from .Values.conf.keystone.pool_maxsize
{{ if not .Values.conf.keystone.pool_maxsize }}#{{ end }}pool_maxsize = {{ .Values.conf.keystone.pool_maxsize | default "10" }}

# Number of seconds a connection to memcached is held unused in the pool before
# it is closed. This is used by the key value store system. (integer value)
# from .Values.conf.keystone.pool_unused_timeout
{{ if not .Values.conf.keystone.pool_unused_timeout }}#{{ end }}pool_unused_timeout = {{ .Values.conf.keystone.pool_unused_timeout | default "60" }}

# Number of seconds that an operation will wait to get a memcache client
# connection. This is used by the key value store system. (integer value)
# from .Values.conf.keystone.pool_connection_get_timeout
{{ if not .Values.conf.keystone.pool_connection_get_timeout }}#{{ end }}pool_connection_get_timeout = {{ .Values.conf.keystone.pool_connection_get_timeout | default "10" }}


[oauth1]

#
# From keystone
#

# Entry point for the OAuth backend driver in the `keystone.oauth1` namespace.
# Typically, there is no reason to set this option unless you are providing a
# custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Number of seconds for the OAuth Request Token to remain valid after being
# created. This is the amount of time the user has to authorize the token.
# Setting this option to zero means that request tokens will last forever.
# (integer value)
# Minimum value: 0
# from .Values.conf.keystone.request_token_duration
{{ if not .Values.conf.keystone.request_token_duration }}#{{ end }}request_token_duration = {{ .Values.conf.keystone.request_token_duration | default "28800" }}

# Number of seconds for the OAuth Access Token to remain valid after being
# created. This is the amount of time the consumer has to interact with the
# service provider (which is typically keystone). Setting this option to zero
# means that access tokens will last forever. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.access_token_duration
{{ if not .Values.conf.keystone.access_token_duration }}#{{ end }}access_token_duration = {{ .Values.conf.keystone.access_token_duration | default "86400" }}


[oslo_messaging_amqp]

#
# From oslo.messaging
#

# Name for the AMQP container. must be globally unique. Defaults to a generated
# UUID (string value)
# Deprecated group/name - [amqp1]/container_name
# from .Values.conf.oslo.messaging.container_name
{{ if not .Values.conf.oslo.messaging.container_name }}#{{ end }}container_name = {{ .Values.conf.oslo.messaging.container_name | default "<None>" }}

# Timeout for inactive connections (in seconds) (integer value)
# Deprecated group/name - [amqp1]/idle_timeout
# from .Values.conf.oslo.messaging.idle_timeout
{{ if not .Values.conf.oslo.messaging.idle_timeout }}#{{ end }}idle_timeout = {{ .Values.conf.oslo.messaging.idle_timeout | default "0" }}

# Debug: dump AMQP frames to stdout (boolean value)
# Deprecated group/name - [amqp1]/trace
# from .Values.conf.oslo.messaging.trace
{{ if not .Values.conf.oslo.messaging.trace }}#{{ end }}trace = {{ .Values.conf.oslo.messaging.trace | default "false" }}

# CA certificate PEM file used to verify the server's certificate (string
# value)
# Deprecated group/name - [amqp1]/ssl_ca_file
# from .Values.conf.oslo.messaging.ssl_ca_file
{{ if not .Values.conf.oslo.messaging.ssl_ca_file }}#{{ end }}ssl_ca_file = {{ .Values.conf.oslo.messaging.ssl_ca_file | default "" }}

# Self-identifying certificate PEM file for client authentication (string
# value)
# Deprecated group/name - [amqp1]/ssl_cert_file
# from .Values.conf.oslo.messaging.ssl_cert_file
{{ if not .Values.conf.oslo.messaging.ssl_cert_file }}#{{ end }}ssl_cert_file = {{ .Values.conf.oslo.messaging.ssl_cert_file | default "" }}

# Private key PEM file used to sign ssl_cert_file certificate (optional)
# (string value)
# Deprecated group/name - [amqp1]/ssl_key_file
# from .Values.conf.oslo.messaging.ssl_key_file
{{ if not .Values.conf.oslo.messaging.ssl_key_file }}#{{ end }}ssl_key_file = {{ .Values.conf.oslo.messaging.ssl_key_file | default "" }}

# Password for decrypting ssl_key_file (if encrypted) (string value)
# Deprecated group/name - [amqp1]/ssl_key_password
# from .Values.conf.oslo.messaging.ssl_key_password
{{ if not .Values.conf.oslo.messaging.ssl_key_password }}#{{ end }}ssl_key_password = {{ .Values.conf.oslo.messaging.ssl_key_password | default "<None>" }}

# DEPRECATED: Accept clients using either SSL or plain TCP (boolean value)
# Deprecated group/name - [amqp1]/allow_insecure_clients
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Not applicable - not a SSL server
# from .Values.conf.oslo.messaging.allow_insecure_clients
{{ if not .Values.conf.oslo.messaging.allow_insecure_clients }}#{{ end }}allow_insecure_clients = {{ .Values.conf.oslo.messaging.allow_insecure_clients | default "false" }}

# Space separated list of acceptable SASL mechanisms (string value)
# Deprecated group/name - [amqp1]/sasl_mechanisms
# from .Values.conf.oslo.messaging.sasl_mechanisms
{{ if not .Values.conf.oslo.messaging.sasl_mechanisms }}#{{ end }}sasl_mechanisms = {{ .Values.conf.oslo.messaging.sasl_mechanisms | default "" }}

# Path to directory that contains the SASL configuration (string value)
# Deprecated group/name - [amqp1]/sasl_config_dir
# from .Values.conf.oslo.messaging.sasl_config_dir
{{ if not .Values.conf.oslo.messaging.sasl_config_dir }}#{{ end }}sasl_config_dir = {{ .Values.conf.oslo.messaging.sasl_config_dir | default "" }}

# Name of configuration file (without .conf suffix) (string value)
# Deprecated group/name - [amqp1]/sasl_config_name
# from .Values.conf.oslo.messaging.sasl_config_name
{{ if not .Values.conf.oslo.messaging.sasl_config_name }}#{{ end }}sasl_config_name = {{ .Values.conf.oslo.messaging.sasl_config_name | default "" }}

# User name for message broker authentication (string value)
# Deprecated group/name - [amqp1]/username
# from .Values.conf.oslo.messaging.username
{{ if not .Values.conf.oslo.messaging.username }}#{{ end }}username = {{ .Values.conf.oslo.messaging.username | default "" }}

# Password for message broker authentication (string value)
# Deprecated group/name - [amqp1]/password
# from .Values.conf.oslo.messaging.password
{{ if not .Values.conf.oslo.messaging.password }}#{{ end }}password = {{ .Values.conf.oslo.messaging.password | default "" }}

# Seconds to pause before attempting to re-connect. (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.connection_retry_interval
{{ if not .Values.conf.oslo.messaging.connection_retry_interval }}#{{ end }}connection_retry_interval = {{ .Values.conf.oslo.messaging.connection_retry_interval | default "1" }}

# Increase the connection_retry_interval by this many seconds after each
# unsuccessful failover attempt. (integer value)
# Minimum value: 0
# from .Values.conf.oslo.messaging.connection_retry_backoff
{{ if not .Values.conf.oslo.messaging.connection_retry_backoff }}#{{ end }}connection_retry_backoff = {{ .Values.conf.oslo.messaging.connection_retry_backoff | default "2" }}

# Maximum limit for connection_retry_interval + connection_retry_backoff
# (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.connection_retry_interval_max
{{ if not .Values.conf.oslo.messaging.connection_retry_interval_max }}#{{ end }}connection_retry_interval_max = {{ .Values.conf.oslo.messaging.connection_retry_interval_max | default "30" }}

# Time to pause between re-connecting an AMQP 1.0 link that failed due to a
# recoverable error. (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.link_retry_delay
{{ if not .Values.conf.oslo.messaging.link_retry_delay }}#{{ end }}link_retry_delay = {{ .Values.conf.oslo.messaging.link_retry_delay | default "10" }}

# The maximum number of attempts to re-send a reply message which failed due to
# a recoverable error. (integer value)
# Minimum value: -1
# from .Values.conf.oslo.messaging.default_reply_retry
{{ if not .Values.conf.oslo.messaging.default_reply_retry }}#{{ end }}default_reply_retry = {{ .Values.conf.oslo.messaging.default_reply_retry | default "0" }}

# The deadline for an rpc reply message delivery. (integer value)
# Minimum value: 5
# from .Values.conf.oslo.messaging.default_reply_timeout
{{ if not .Values.conf.oslo.messaging.default_reply_timeout }}#{{ end }}default_reply_timeout = {{ .Values.conf.oslo.messaging.default_reply_timeout | default "30" }}

# The deadline for an rpc cast or call message delivery. Only used when caller
# does not provide a timeout expiry. (integer value)
# Minimum value: 5
# from .Values.conf.oslo.messaging.default_send_timeout
{{ if not .Values.conf.oslo.messaging.default_send_timeout }}#{{ end }}default_send_timeout = {{ .Values.conf.oslo.messaging.default_send_timeout | default "30" }}

# The deadline for a sent notification message delivery. Only used when caller
# does not provide a timeout expiry. (integer value)
# Minimum value: 5
# from .Values.conf.oslo.messaging.default_notify_timeout
{{ if not .Values.conf.oslo.messaging.default_notify_timeout }}#{{ end }}default_notify_timeout = {{ .Values.conf.oslo.messaging.default_notify_timeout | default "30" }}

# The duration to schedule a purge of idle sender links. Detach link after
# expiry. (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.default_sender_link_timeout
{{ if not .Values.conf.oslo.messaging.default_sender_link_timeout }}#{{ end }}default_sender_link_timeout = {{ .Values.conf.oslo.messaging.default_sender_link_timeout | default "600" }}

# Indicates the addressing mode used by the driver.
# Permitted values:
# 'legacy'   - use legacy non-routable addressing
# 'routable' - use routable addresses
# 'dynamic'  - use legacy addresses if the message bus does not support routing
# otherwise use routable addressing (string value)
# from .Values.conf.oslo.messaging.addressing_mode
{{ if not .Values.conf.oslo.messaging.addressing_mode }}#{{ end }}addressing_mode = {{ .Values.conf.oslo.messaging.addressing_mode | default "dynamic" }}

# address prefix used when sending to a specific server (string value)
# Deprecated group/name - [amqp1]/server_request_prefix
# from .Values.conf.oslo.messaging.server_request_prefix
{{ if not .Values.conf.oslo.messaging.server_request_prefix }}#{{ end }}server_request_prefix = {{ .Values.conf.oslo.messaging.server_request_prefix | default "exclusive" }}

# address prefix used when broadcasting to all servers (string value)
# Deprecated group/name - [amqp1]/broadcast_prefix
# from .Values.conf.oslo.messaging.broadcast_prefix
{{ if not .Values.conf.oslo.messaging.broadcast_prefix }}#{{ end }}broadcast_prefix = {{ .Values.conf.oslo.messaging.broadcast_prefix | default "broadcast" }}

# address prefix when sending to any server in group (string value)
# Deprecated group/name - [amqp1]/group_request_prefix
# from .Values.conf.oslo.messaging.group_request_prefix
{{ if not .Values.conf.oslo.messaging.group_request_prefix }}#{{ end }}group_request_prefix = {{ .Values.conf.oslo.messaging.group_request_prefix | default "unicast" }}

# Address prefix for all generated RPC addresses (string value)
# from .Values.conf.oslo.messaging.rpc_address_prefix
{{ if not .Values.conf.oslo.messaging.rpc_address_prefix }}#{{ end }}rpc_address_prefix = {{ .Values.conf.oslo.messaging.rpc_address_prefix | default "openstack.org/om/rpc" }}

# Address prefix for all generated Notification addresses (string value)
# from .Values.conf.oslo.messaging.notify_address_prefix
{{ if not .Values.conf.oslo.messaging.notify_address_prefix }}#{{ end }}notify_address_prefix = {{ .Values.conf.oslo.messaging.notify_address_prefix | default "openstack.org/om/notify" }}

# Appended to the address prefix when sending a fanout message. Used by the
# message bus to identify fanout messages. (string value)
# from .Values.conf.oslo.messaging.multicast_address
{{ if not .Values.conf.oslo.messaging.multicast_address }}#{{ end }}multicast_address = {{ .Values.conf.oslo.messaging.multicast_address | default "multicast" }}

# Appended to the address prefix when sending to a particular RPC/Notification
# server. Used by the message bus to identify messages sent to a single
# destination. (string value)
# from .Values.conf.oslo.messaging.unicast_address
{{ if not .Values.conf.oslo.messaging.unicast_address }}#{{ end }}unicast_address = {{ .Values.conf.oslo.messaging.unicast_address | default "unicast" }}

# Appended to the address prefix when sending to a group of consumers. Used by
# the message bus to identify messages that should be delivered in a round-
# robin fashion across consumers. (string value)
# from .Values.conf.oslo.messaging.anycast_address
{{ if not .Values.conf.oslo.messaging.anycast_address }}#{{ end }}anycast_address = {{ .Values.conf.oslo.messaging.anycast_address | default "anycast" }}

# Exchange name used in notification addresses.
# Exchange name resolution precedence:
# Target.exchange if set
# else default_notification_exchange if set
# else control_exchange if set
# else 'notify' (string value)
# from .Values.conf.oslo.messaging.default_notification_exchange
{{ if not .Values.conf.oslo.messaging.default_notification_exchange }}#{{ end }}default_notification_exchange = {{ .Values.conf.oslo.messaging.default_notification_exchange | default "<None>" }}

# Exchange name used in RPC addresses.
# Exchange name resolution precedence:
# Target.exchange if set
# else default_rpc_exchange if set
# else control_exchange if set
# else 'rpc' (string value)
# from .Values.conf.oslo.messaging.default_rpc_exchange
{{ if not .Values.conf.oslo.messaging.default_rpc_exchange }}#{{ end }}default_rpc_exchange = {{ .Values.conf.oslo.messaging.default_rpc_exchange | default "<None>" }}

# Window size for incoming RPC Reply messages. (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.reply_link_credit
{{ if not .Values.conf.oslo.messaging.reply_link_credit }}#{{ end }}reply_link_credit = {{ .Values.conf.oslo.messaging.reply_link_credit | default "200" }}

# Window size for incoming RPC Request messages (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.rpc_server_credit
{{ if not .Values.conf.oslo.messaging.rpc_server_credit }}#{{ end }}rpc_server_credit = {{ .Values.conf.oslo.messaging.rpc_server_credit | default "100" }}

# Window size for incoming Notification messages (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.notify_server_credit
{{ if not .Values.conf.oslo.messaging.notify_server_credit }}#{{ end }}notify_server_credit = {{ .Values.conf.oslo.messaging.notify_server_credit | default "100" }}

# Send messages of this type pre-settled.
# Pre-settled messages will not receive acknowledgement
# from the peer. Note well: pre-settled messages may be
# silently discarded if the delivery fails.
# Permitted values:
# 'rpc-call' - send RPC Calls pre-settled
# 'rpc-reply'- send RPC Replies pre-settled
# 'rpc-cast' - Send RPC Casts pre-settled
# 'notify'   - Send Notifications pre-settled
#  (multi valued)
# from .Values.conf.oslo.messaging.pre_settled
{{ if not .Values.conf.oslo.messaging.pre_settled }}#{{ end }}pre_settled = {{ .Values.conf.oslo.messaging.pre_settled | default "rpc-cast" }}
# from .Values.conf.oslo.messaging.pre_settled
{{ if not .Values.conf.oslo.messaging.pre_settled }}#{{ end }}pre_settled = {{ .Values.conf.oslo.messaging.pre_settled | default "rpc-reply" }}


[oslo_messaging_kafka]

#
# From oslo.messaging
#

# DEPRECATED: Default Kafka broker Host (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.kafka_default_host
{{ if not .Values.conf.oslo.messaging.kafka_default_host }}#{{ end }}kafka_default_host = {{ .Values.conf.oslo.messaging.kafka_default_host | default "localhost" }}

# DEPRECATED: Default Kafka broker Port (port value)
# Minimum value: 0
# Maximum value: 65535
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.kafka_default_port
{{ if not .Values.conf.oslo.messaging.kafka_default_port }}#{{ end }}kafka_default_port = {{ .Values.conf.oslo.messaging.kafka_default_port | default "9092" }}

# Max fetch bytes of Kafka consumer (integer value)
# from .Values.conf.oslo.messaging.kafka_max_fetch_bytes
{{ if not .Values.conf.oslo.messaging.kafka_max_fetch_bytes }}#{{ end }}kafka_max_fetch_bytes = {{ .Values.conf.oslo.messaging.kafka_max_fetch_bytes | default "1048576" }}

# Default timeout(s) for Kafka consumers (integer value)
# from .Values.conf.oslo.messaging.kafka_consumer_timeout
{{ if not .Values.conf.oslo.messaging.kafka_consumer_timeout }}#{{ end }}kafka_consumer_timeout = {{ .Values.conf.oslo.messaging.kafka_consumer_timeout | default "1.0" }}

# Pool Size for Kafka Consumers (integer value)
# from .Values.conf.oslo.messaging.pool_size
{{ if not .Values.conf.oslo.messaging.pool_size }}#{{ end }}pool_size = {{ .Values.conf.oslo.messaging.pool_size | default "10" }}

# The pool size limit for connections expiration policy (integer value)
# from .Values.conf.oslo.messaging.conn_pool_min_size
{{ if not .Values.conf.oslo.messaging.conn_pool_min_size }}#{{ end }}conn_pool_min_size = {{ .Values.conf.oslo.messaging.conn_pool_min_size | default "2" }}

# The time-to-live in sec of idle connections in the pool (integer value)
# from .Values.conf.oslo.messaging.conn_pool_ttl
{{ if not .Values.conf.oslo.messaging.conn_pool_ttl }}#{{ end }}conn_pool_ttl = {{ .Values.conf.oslo.messaging.conn_pool_ttl | default "1200" }}

# Group id for Kafka consumer. Consumers in one group will coordinate message
# consumption (string value)
# from .Values.conf.oslo.messaging.consumer_group
{{ if not .Values.conf.oslo.messaging.consumer_group }}#{{ end }}consumer_group = {{ .Values.conf.oslo.messaging.consumer_group | default "oslo_messaging_consumer" }}

# Upper bound on the delay for KafkaProducer batching in seconds (floating
# point value)
# from .Values.conf.oslo.messaging.producer_batch_timeout
{{ if not .Values.conf.oslo.messaging.producer_batch_timeout }}#{{ end }}producer_batch_timeout = {{ .Values.conf.oslo.messaging.producer_batch_timeout | default "0.0" }}

# Size of batch for the producer async send (integer value)
# from .Values.conf.oslo.messaging.producer_batch_size
{{ if not .Values.conf.oslo.messaging.producer_batch_size }}#{{ end }}producer_batch_size = {{ .Values.conf.oslo.messaging.producer_batch_size | default "16384" }}


[oslo_messaging_notifications]

#
# From oslo.messaging
#

# The Drivers(s) to handle sending notifications. Possible values are
# messaging, messagingv2, routing, log, test, noop (multi valued)
# Deprecated group/name - [DEFAULT]/notification_driver
# from .Values.conf.oslo.messaging.driver
{{ if not .Values.conf.oslo.messaging.driver }}#{{ end }}driver = {{ .Values.conf.oslo.messaging.driver | default "" }}

# A URL representing the messaging driver to use for notifications. If not set,
# we fall back to the same configuration used for RPC. (string value)
# Deprecated group/name - [DEFAULT]/notification_transport_url
# from .Values.conf.oslo.messaging.transport_url
{{ if not .Values.conf.oslo.messaging.transport_url }}#{{ end }}transport_url = {{ .Values.conf.oslo.messaging.transport_url | default "<None>" }}

# AMQP topic used for OpenStack notifications. (list value)
# Deprecated group/name - [rpc_notifier2]/topics
# Deprecated group/name - [DEFAULT]/notification_topics
# from .Values.conf.oslo.messaging.topics
{{ if not .Values.conf.oslo.messaging.topics }}#{{ end }}topics = {{ .Values.conf.oslo.messaging.topics | default "notifications" }}


[oslo_messaging_rabbit]

#
# From oslo.messaging
#

# Use durable queues in AMQP. (boolean value)
# Deprecated group/name - [DEFAULT]/amqp_durable_queues
# Deprecated group/name - [DEFAULT]/rabbit_durable_queues
# from .Values.conf.oslo.messaging.amqp_durable_queues
{{ if not .Values.conf.oslo.messaging.amqp_durable_queues }}#{{ end }}amqp_durable_queues = {{ .Values.conf.oslo.messaging.amqp_durable_queues | default "false" }}

# Auto-delete queues in AMQP. (boolean value)
# Deprecated group/name - [DEFAULT]/amqp_auto_delete
# from .Values.conf.oslo.messaging.amqp_auto_delete
{{ if not .Values.conf.oslo.messaging.amqp_auto_delete }}#{{ end }}amqp_auto_delete = {{ .Values.conf.oslo.messaging.amqp_auto_delete | default "false" }}

# SSL version to use (valid only if SSL enabled). Valid values are TLSv1 and
# SSLv23. SSLv2, SSLv3, TLSv1_1, and TLSv1_2 may be available on some
# distributions. (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_version
# from .Values.conf.oslo.messaging.kombu_ssl_version
{{ if not .Values.conf.oslo.messaging.kombu_ssl_version }}#{{ end }}kombu_ssl_version = {{ .Values.conf.oslo.messaging.kombu_ssl_version | default "" }}

# SSL key file (valid only if SSL enabled). (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_keyfile
# from .Values.conf.oslo.messaging.kombu_ssl_keyfile
{{ if not .Values.conf.oslo.messaging.kombu_ssl_keyfile }}#{{ end }}kombu_ssl_keyfile = {{ .Values.conf.oslo.messaging.kombu_ssl_keyfile | default "" }}

# SSL cert file (valid only if SSL enabled). (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_certfile
# from .Values.conf.oslo.messaging.kombu_ssl_certfile
{{ if not .Values.conf.oslo.messaging.kombu_ssl_certfile }}#{{ end }}kombu_ssl_certfile = {{ .Values.conf.oslo.messaging.kombu_ssl_certfile | default "" }}

# SSL certification authority file (valid only if SSL enabled). (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_ca_certs
# from .Values.conf.oslo.messaging.kombu_ssl_ca_certs
{{ if not .Values.conf.oslo.messaging.kombu_ssl_ca_certs }}#{{ end }}kombu_ssl_ca_certs = {{ .Values.conf.oslo.messaging.kombu_ssl_ca_certs | default "" }}

# How long to wait before reconnecting in response to an AMQP consumer cancel
# notification. (floating point value)
# Deprecated group/name - [DEFAULT]/kombu_reconnect_delay
# from .Values.conf.oslo.messaging.kombu_reconnect_delay
{{ if not .Values.conf.oslo.messaging.kombu_reconnect_delay }}#{{ end }}kombu_reconnect_delay = {{ .Values.conf.oslo.messaging.kombu_reconnect_delay | default "1.0" }}

# EXPERIMENTAL: Possible values are: gzip, bz2. If not set compression will not
# be used. This option may not be available in future versions. (string value)
# from .Values.conf.oslo.messaging.kombu_compression
{{ if not .Values.conf.oslo.messaging.kombu_compression }}#{{ end }}kombu_compression = {{ .Values.conf.oslo.messaging.kombu_compression | default "<None>" }}

# How long to wait a missing client before abandoning to send it its replies.
# This value should not be longer than rpc_response_timeout. (integer value)
# Deprecated group/name - [oslo_messaging_rabbit]/kombu_reconnect_timeout
# from .Values.conf.oslo.messaging.kombu_missing_consumer_retry_timeout
{{ if not .Values.conf.oslo.messaging.kombu_missing_consumer_retry_timeout }}#{{ end }}kombu_missing_consumer_retry_timeout = {{ .Values.conf.oslo.messaging.kombu_missing_consumer_retry_timeout | default "60" }}

# Determines how the next RabbitMQ node is chosen in case the one we are
# currently connected to becomes unavailable. Takes effect only if more than
# one RabbitMQ node is provided in config. (string value)
# Allowed values: round-robin, shuffle
# from .Values.conf.oslo.messaging.kombu_failover_strategy
{{ if not .Values.conf.oslo.messaging.kombu_failover_strategy }}#{{ end }}kombu_failover_strategy = {{ .Values.conf.oslo.messaging.kombu_failover_strategy | default "round-robin" }}

# DEPRECATED: The RabbitMQ broker address where a single node is used. (string
# value)
# Deprecated group/name - [DEFAULT]/rabbit_host
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_host
{{ if not .Values.conf.oslo.messaging.rabbit_host }}#{{ end }}rabbit_host = {{ .Values.conf.oslo.messaging.rabbit_host | default "localhost" }}

# DEPRECATED: The RabbitMQ broker port where a single node is used. (port
# value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rabbit_port
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_port
{{ if not .Values.conf.oslo.messaging.rabbit_port }}#{{ end }}rabbit_port = {{ .Values.conf.oslo.messaging.rabbit_port | default "5672" }}

# DEPRECATED: RabbitMQ HA cluster host:port pairs. (list value)
# Deprecated group/name - [DEFAULT]/rabbit_hosts
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_hosts
{{ if not .Values.conf.oslo.messaging.rabbit_hosts }}#{{ end }}rabbit_hosts = {{ .Values.conf.oslo.messaging.rabbit_hosts | default "$rabbit_host:$rabbit_port" }}

# Connect over SSL for RabbitMQ. (boolean value)
# Deprecated group/name - [DEFAULT]/rabbit_use_ssl
# from .Values.conf.oslo.messaging.rabbit_use_ssl
{{ if not .Values.conf.oslo.messaging.rabbit_use_ssl }}#{{ end }}rabbit_use_ssl = {{ .Values.conf.oslo.messaging.rabbit_use_ssl | default "false" }}

# DEPRECATED: The RabbitMQ userid. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_userid
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_userid
{{ if not .Values.conf.oslo.messaging.rabbit_userid }}#{{ end }}rabbit_userid = {{ .Values.conf.oslo.messaging.rabbit_userid | default "guest" }}

# DEPRECATED: The RabbitMQ password. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_password
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_password
{{ if not .Values.conf.oslo.messaging.rabbit_password }}#{{ end }}rabbit_password = {{ .Values.conf.oslo.messaging.rabbit_password | default "guest" }}

# The RabbitMQ login method. (string value)
# Allowed values: PLAIN, AMQPLAIN, RABBIT-CR-DEMO
# Deprecated group/name - [DEFAULT]/rabbit_login_method
# from .Values.conf.oslo.messaging.rabbit_login_method
{{ if not .Values.conf.oslo.messaging.rabbit_login_method }}#{{ end }}rabbit_login_method = {{ .Values.conf.oslo.messaging.rabbit_login_method | default "AMQPLAIN" }}

# DEPRECATED: The RabbitMQ virtual host. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_virtual_host
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .Values.conf.oslo.messaging.rabbit_virtual_host
{{ if not .Values.conf.oslo.messaging.rabbit_virtual_host }}#{{ end }}rabbit_virtual_host = {{ .Values.conf.oslo.messaging.rabbit_virtual_host | default "/" }}

# How frequently to retry connecting with RabbitMQ. (integer value)
# from .Values.conf.oslo.messaging.rabbit_retry_interval
{{ if not .Values.conf.oslo.messaging.rabbit_retry_interval }}#{{ end }}rabbit_retry_interval = {{ .Values.conf.oslo.messaging.rabbit_retry_interval | default "1" }}

# How long to backoff for between retries when connecting to RabbitMQ. (integer
# value)
# Deprecated group/name - [DEFAULT]/rabbit_retry_backoff
# from .Values.conf.oslo.messaging.rabbit_retry_backoff
{{ if not .Values.conf.oslo.messaging.rabbit_retry_backoff }}#{{ end }}rabbit_retry_backoff = {{ .Values.conf.oslo.messaging.rabbit_retry_backoff | default "2" }}

# Maximum interval of RabbitMQ connection retries. Default is 30 seconds.
# (integer value)
# from .Values.conf.oslo.messaging.rabbit_interval_max
{{ if not .Values.conf.oslo.messaging.rabbit_interval_max }}#{{ end }}rabbit_interval_max = {{ .Values.conf.oslo.messaging.rabbit_interval_max | default "30" }}

# DEPRECATED: Maximum number of RabbitMQ connection retries. Default is 0
# (infinite retry count). (integer value)
# Deprecated group/name - [DEFAULT]/rabbit_max_retries
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .Values.conf.oslo.messaging.rabbit_max_retries
{{ if not .Values.conf.oslo.messaging.rabbit_max_retries }}#{{ end }}rabbit_max_retries = {{ .Values.conf.oslo.messaging.rabbit_max_retries | default "0" }}

# Try to use HA queues in RabbitMQ (x-ha-policy: all). If you change this
# option, you must wipe the RabbitMQ database. In RabbitMQ 3.0, queue mirroring
# is no longer controlled by the x-ha-policy argument when declaring a queue.
# If you just want to make sure that all queues (except those with auto-
# generated names) are mirrored across all nodes, run: "rabbitmqctl set_policy
# HA '^(?!amq\.).*' '{"ha-mode": "all"}' " (boolean value)
# Deprecated group/name - [DEFAULT]/rabbit_ha_queues
# from .Values.conf.oslo.messaging.rabbit_ha_queues
{{ if not .Values.conf.oslo.messaging.rabbit_ha_queues }}#{{ end }}rabbit_ha_queues = {{ .Values.conf.oslo.messaging.rabbit_ha_queues | default "false" }}

# Positive integer representing duration in seconds for queue TTL (x-expires).
# Queues which are unused for the duration of the TTL are automatically
# deleted. The parameter affects only reply and fanout queues. (integer value)
# Minimum value: 1
# from .Values.conf.oslo.messaging.rabbit_transient_queues_ttl
{{ if not .Values.conf.oslo.messaging.rabbit_transient_queues_ttl }}#{{ end }}rabbit_transient_queues_ttl = {{ .Values.conf.oslo.messaging.rabbit_transient_queues_ttl | default "1800" }}

# Specifies the number of messages to prefetch. Setting to zero allows
# unlimited messages. (integer value)
# from .Values.conf.oslo.messaging.rabbit_qos_prefetch_count
{{ if not .Values.conf.oslo.messaging.rabbit_qos_prefetch_count }}#{{ end }}rabbit_qos_prefetch_count = {{ .Values.conf.oslo.messaging.rabbit_qos_prefetch_count | default "0" }}

# Number of seconds after which the Rabbit broker is considered down if
# heartbeat's keep-alive fails (0 disable the heartbeat). EXPERIMENTAL (integer
# value)
# from .Values.conf.oslo.messaging.heartbeat_timeout_threshold
{{ if not .Values.conf.oslo.messaging.heartbeat_timeout_threshold }}#{{ end }}heartbeat_timeout_threshold = {{ .Values.conf.oslo.messaging.heartbeat_timeout_threshold | default "60" }}

# How often times during the heartbeat_timeout_threshold we check the
# heartbeat. (integer value)
# from .Values.conf.oslo.messaging.heartbeat_rate
{{ if not .Values.conf.oslo.messaging.heartbeat_rate }}#{{ end }}heartbeat_rate = {{ .Values.conf.oslo.messaging.heartbeat_rate | default "2" }}

# Deprecated, use rpc_backend=kombu+memory or rpc_backend=fake (boolean value)
# Deprecated group/name - [DEFAULT]/fake_rabbit
# from .Values.conf.oslo.messaging.fake_rabbit
{{ if not .Values.conf.oslo.messaging.fake_rabbit }}#{{ end }}fake_rabbit = {{ .Values.conf.oslo.messaging.fake_rabbit | default "false" }}

# Maximum number of channels to allow (integer value)
# from .Values.conf.oslo.messaging.channel_max
{{ if not .Values.conf.oslo.messaging.channel_max }}#{{ end }}channel_max = {{ .Values.conf.oslo.messaging.channel_max | default "<None>" }}

# The maximum byte size for an AMQP frame (integer value)
# from .Values.conf.oslo.messaging.frame_max
{{ if not .Values.conf.oslo.messaging.frame_max }}#{{ end }}frame_max = {{ .Values.conf.oslo.messaging.frame_max | default "<None>" }}

# How often to send heartbeats for consumer's connections (integer value)
# from .Values.conf.oslo.messaging.heartbeat_interval
{{ if not .Values.conf.oslo.messaging.heartbeat_interval }}#{{ end }}heartbeat_interval = {{ .Values.conf.oslo.messaging.heartbeat_interval | default "3" }}

# Enable SSL (boolean value)
# from .Values.conf.oslo.messaging.ssl
{{ if not .Values.conf.oslo.messaging.ssl }}#{{ end }}ssl = {{ .Values.conf.oslo.messaging.ssl | default "<None>" }}

# Arguments passed to ssl.wrap_socket (dict value)
# from .Values.conf.oslo.messaging.ssl_options
{{ if not .Values.conf.oslo.messaging.ssl_options }}#{{ end }}ssl_options = {{ .Values.conf.oslo.messaging.ssl_options | default "<None>" }}

# Set socket timeout in seconds for connection's socket (floating point value)
# from .Values.conf.oslo.messaging.socket_timeout
{{ if not .Values.conf.oslo.messaging.socket_timeout }}#{{ end }}socket_timeout = {{ .Values.conf.oslo.messaging.socket_timeout | default "0.25" }}

# Set TCP_USER_TIMEOUT in seconds for connection's socket (floating point
# value)
# from .Values.conf.oslo.messaging.tcp_user_timeout
{{ if not .Values.conf.oslo.messaging.tcp_user_timeout }}#{{ end }}tcp_user_timeout = {{ .Values.conf.oslo.messaging.tcp_user_timeout | default "0.25" }}

# Set delay for reconnection to some host which has connection error (floating
# point value)
# from .Values.conf.oslo.messaging.host_connection_reconnect_delay
{{ if not .Values.conf.oslo.messaging.host_connection_reconnect_delay }}#{{ end }}host_connection_reconnect_delay = {{ .Values.conf.oslo.messaging.host_connection_reconnect_delay | default "0.25" }}

# Connection factory implementation (string value)
# Allowed values: new, single, read_write
# from .Values.conf.oslo.messaging.connection_factory
{{ if not .Values.conf.oslo.messaging.connection_factory }}#{{ end }}connection_factory = {{ .Values.conf.oslo.messaging.connection_factory | default "single" }}

# Maximum number of connections to keep queued. (integer value)
# from .Values.conf.oslo.messaging.pool_max_size
{{ if not .Values.conf.oslo.messaging.pool_max_size }}#{{ end }}pool_max_size = {{ .Values.conf.oslo.messaging.pool_max_size | default "30" }}

# Maximum number of connections to create above `pool_max_size`. (integer
# value)
# from .Values.conf.oslo.messaging.pool_max_overflow
{{ if not .Values.conf.oslo.messaging.pool_max_overflow }}#{{ end }}pool_max_overflow = {{ .Values.conf.oslo.messaging.pool_max_overflow | default "0" }}

# Default number of seconds to wait for a connections to available (integer
# value)
# from .Values.conf.oslo.messaging.pool_timeout
{{ if not .Values.conf.oslo.messaging.pool_timeout }}#{{ end }}pool_timeout = {{ .Values.conf.oslo.messaging.pool_timeout | default "30" }}

# Lifetime of a connection (since creation) in seconds or None for no
# recycling. Expired connections are closed on acquire. (integer value)
# from .Values.conf.oslo.messaging.pool_recycle
{{ if not .Values.conf.oslo.messaging.pool_recycle }}#{{ end }}pool_recycle = {{ .Values.conf.oslo.messaging.pool_recycle | default "600" }}

# Threshold at which inactive (since release) connections are considered stale
# in seconds or None for no staleness. Stale connections are closed on acquire.
# (integer value)
# from .Values.conf.oslo.messaging.pool_stale
{{ if not .Values.conf.oslo.messaging.pool_stale }}#{{ end }}pool_stale = {{ .Values.conf.oslo.messaging.pool_stale | default "60" }}

# Default serialization mechanism for serializing/deserializing
# outgoing/incoming messages (string value)
# Allowed values: json, msgpack
# from .Values.conf.oslo.messaging.default_serializer_type
{{ if not .Values.conf.oslo.messaging.default_serializer_type }}#{{ end }}default_serializer_type = {{ .Values.conf.oslo.messaging.default_serializer_type | default "json" }}

# Persist notification messages. (boolean value)
# from .Values.conf.oslo.messaging.notification_persistence
{{ if not .Values.conf.oslo.messaging.notification_persistence }}#{{ end }}notification_persistence = {{ .Values.conf.oslo.messaging.notification_persistence | default "false" }}

# Exchange name for sending notifications (string value)
# from .Values.conf.oslo.messaging.default_notification_exchange
{{ if not .Values.conf.oslo.messaging.default_notification_exchange }}#{{ end }}default_notification_exchange = {{ .Values.conf.oslo.messaging.default_notification_exchange | default "${control_exchange}_notification" }}

# Max number of not acknowledged message which RabbitMQ can send to
# notification listener. (integer value)
# from .Values.conf.oslo.messaging.notification_listener_prefetch_count
{{ if not .Values.conf.oslo.messaging.notification_listener_prefetch_count }}#{{ end }}notification_listener_prefetch_count = {{ .Values.conf.oslo.messaging.notification_listener_prefetch_count | default "100" }}

# Reconnecting retry count in case of connectivity problem during sending
# notification, -1 means infinite retry. (integer value)
# from .Values.conf.oslo.messaging.default_notification_retry_attempts
{{ if not .Values.conf.oslo.messaging.default_notification_retry_attempts }}#{{ end }}default_notification_retry_attempts = {{ .Values.conf.oslo.messaging.default_notification_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during sending
# notification message (floating point value)
# from .Values.conf.oslo.messaging.notification_retry_delay
{{ if not .Values.conf.oslo.messaging.notification_retry_delay }}#{{ end }}notification_retry_delay = {{ .Values.conf.oslo.messaging.notification_retry_delay | default "0.25" }}

# Time to live for rpc queues without consumers in seconds. (integer value)
# from .Values.conf.oslo.messaging.rpc_queue_expiration
{{ if not .Values.conf.oslo.messaging.rpc_queue_expiration }}#{{ end }}rpc_queue_expiration = {{ .Values.conf.oslo.messaging.rpc_queue_expiration | default "60" }}

# Exchange name for sending RPC messages (string value)
# from .Values.conf.oslo.messaging.default_rpc_exchange
{{ if not .Values.conf.oslo.messaging.default_rpc_exchange }}#{{ end }}default_rpc_exchange = {{ .Values.conf.oslo.messaging.default_rpc_exchange | default "${control_exchange}_rpc" }}

# Exchange name for receiving RPC replies (string value)
# from .Values.conf.oslo.messaging.rpc_reply_exchange
{{ if not .Values.conf.oslo.messaging.rpc_reply_exchange }}#{{ end }}rpc_reply_exchange = {{ .Values.conf.oslo.messaging.rpc_reply_exchange | default "${control_exchange}_rpc_reply" }}

# Max number of not acknowledged message which RabbitMQ can send to rpc
# listener. (integer value)
# from .Values.conf.oslo.messaging.rpc_listener_prefetch_count
{{ if not .Values.conf.oslo.messaging.rpc_listener_prefetch_count }}#{{ end }}rpc_listener_prefetch_count = {{ .Values.conf.oslo.messaging.rpc_listener_prefetch_count | default "100" }}

# Max number of not acknowledged message which RabbitMQ can send to rpc reply
# listener. (integer value)
# from .Values.conf.oslo.messaging.rpc_reply_listener_prefetch_count
{{ if not .Values.conf.oslo.messaging.rpc_reply_listener_prefetch_count }}#{{ end }}rpc_reply_listener_prefetch_count = {{ .Values.conf.oslo.messaging.rpc_reply_listener_prefetch_count | default "100" }}

# Reconnecting retry count in case of connectivity problem during sending
# reply. -1 means infinite retry during rpc_timeout (integer value)
# from .Values.conf.oslo.messaging.rpc_reply_retry_attempts
{{ if not .Values.conf.oslo.messaging.rpc_reply_retry_attempts }}#{{ end }}rpc_reply_retry_attempts = {{ .Values.conf.oslo.messaging.rpc_reply_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during sending
# reply. (floating point value)
# from .Values.conf.oslo.messaging.rpc_reply_retry_delay
{{ if not .Values.conf.oslo.messaging.rpc_reply_retry_delay }}#{{ end }}rpc_reply_retry_delay = {{ .Values.conf.oslo.messaging.rpc_reply_retry_delay | default "0.25" }}

# Reconnecting retry count in case of connectivity problem during sending RPC
# message, -1 means infinite retry. If actual retry attempts in not 0 the rpc
# request could be processed more than one time (integer value)
# from .Values.conf.oslo.messaging.default_rpc_retry_attempts
{{ if not .Values.conf.oslo.messaging.default_rpc_retry_attempts }}#{{ end }}default_rpc_retry_attempts = {{ .Values.conf.oslo.messaging.default_rpc_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during sending RPC
# message (floating point value)
# from .Values.conf.oslo.messaging.rpc_retry_delay
{{ if not .Values.conf.oslo.messaging.rpc_retry_delay }}#{{ end }}rpc_retry_delay = {{ .Values.conf.oslo.messaging.rpc_retry_delay | default "0.25" }}


[oslo_messaging_zmq]

#
# From oslo.messaging
#

# ZeroMQ bind address. Should be a wildcard (*), an ethernet interface, or IP.
# The "host" option should point or resolve to this address. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_address
# from .Values.conf.oslo.messaging.rpc_zmq_bind_address
{{ if not .Values.conf.oslo.messaging.rpc_zmq_bind_address }}#{{ end }}rpc_zmq_bind_address = {{ .Values.conf.oslo.messaging.rpc_zmq_bind_address | default "*" }}

# MatchMaker driver. (string value)
# Allowed values: redis, sentinel, dummy
# Deprecated group/name - [DEFAULT]/rpc_zmq_matchmaker
# from .Values.conf.oslo.messaging.rpc_zmq_matchmaker
{{ if not .Values.conf.oslo.messaging.rpc_zmq_matchmaker }}#{{ end }}rpc_zmq_matchmaker = {{ .Values.conf.oslo.messaging.rpc_zmq_matchmaker | default "redis" }}

# Number of ZeroMQ contexts, defaults to 1. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_contexts
# from .Values.conf.oslo.messaging.rpc_zmq_contexts
{{ if not .Values.conf.oslo.messaging.rpc_zmq_contexts }}#{{ end }}rpc_zmq_contexts = {{ .Values.conf.oslo.messaging.rpc_zmq_contexts | default "1" }}

# Maximum number of ingress messages to locally buffer per topic. Default is
# unlimited. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_topic_backlog
# from .Values.conf.oslo.messaging.rpc_zmq_topic_backlog
{{ if not .Values.conf.oslo.messaging.rpc_zmq_topic_backlog }}#{{ end }}rpc_zmq_topic_backlog = {{ .Values.conf.oslo.messaging.rpc_zmq_topic_backlog | default "<None>" }}

# Directory for holding IPC sockets. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_ipc_dir
# from .Values.conf.oslo.messaging.rpc_zmq_ipc_dir
{{ if not .Values.conf.oslo.messaging.rpc_zmq_ipc_dir }}#{{ end }}rpc_zmq_ipc_dir = {{ .Values.conf.oslo.messaging.rpc_zmq_ipc_dir | default "/var/run/openstack" }}

# Name of this node. Must be a valid hostname, FQDN, or IP address. Must match
# "host" option, if running Nova. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_host
# from .Values.conf.oslo.messaging.rpc_zmq_host
{{ if not .Values.conf.oslo.messaging.rpc_zmq_host }}#{{ end }}rpc_zmq_host = {{ .Values.conf.oslo.messaging.rpc_zmq_host | default "localhost" }}

# Number of seconds to wait before all pending messages will be sent after
# closing a socket. The default value of -1 specifies an infinite linger
# period. The value of 0 specifies no linger period. Pending messages shall be
# discarded immediately when the socket is closed. Positive values specify an
# upper bound for the linger period. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_cast_timeout
# from .Values.conf.oslo.messaging.zmq_linger
{{ if not .Values.conf.oslo.messaging.zmq_linger }}#{{ end }}zmq_linger = {{ .Values.conf.oslo.messaging.zmq_linger | default "-1" }}

# The default number of seconds that poll should wait. Poll raises timeout
# exception when timeout expired. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_poll_timeout
# from .Values.conf.oslo.messaging.rpc_poll_timeout
{{ if not .Values.conf.oslo.messaging.rpc_poll_timeout }}#{{ end }}rpc_poll_timeout = {{ .Values.conf.oslo.messaging.rpc_poll_timeout | default "1" }}

# Expiration timeout in seconds of a name service record about existing target
# ( < 0 means no timeout). (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_expire
# from .Values.conf.oslo.messaging.zmq_target_expire
{{ if not .Values.conf.oslo.messaging.zmq_target_expire }}#{{ end }}zmq_target_expire = {{ .Values.conf.oslo.messaging.zmq_target_expire | default "300" }}

# Update period in seconds of a name service record about existing target.
# (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_update
# from .Values.conf.oslo.messaging.zmq_target_update
{{ if not .Values.conf.oslo.messaging.zmq_target_update }}#{{ end }}zmq_target_update = {{ .Values.conf.oslo.messaging.zmq_target_update | default "180" }}

# Use PUB/SUB pattern for fanout methods. PUB/SUB always uses proxy. (boolean
# value)
# Deprecated group/name - [DEFAULT]/use_pub_sub
# from .Values.conf.oslo.messaging.use_pub_sub
{{ if not .Values.conf.oslo.messaging.use_pub_sub }}#{{ end }}use_pub_sub = {{ .Values.conf.oslo.messaging.use_pub_sub | default "false" }}

# Use ROUTER remote proxy. (boolean value)
# Deprecated group/name - [DEFAULT]/use_router_proxy
# from .Values.conf.oslo.messaging.use_router_proxy
{{ if not .Values.conf.oslo.messaging.use_router_proxy }}#{{ end }}use_router_proxy = {{ .Values.conf.oslo.messaging.use_router_proxy | default "false" }}

# This option makes direct connections dynamic or static. It makes sense only
# with use_router_proxy=False which means to use direct connections for direct
# message types (ignored otherwise). (boolean value)
# from .Values.conf.oslo.messaging.use_dynamic_connections
{{ if not .Values.conf.oslo.messaging.use_dynamic_connections }}#{{ end }}use_dynamic_connections = {{ .Values.conf.oslo.messaging.use_dynamic_connections | default "false" }}

# How many additional connections to a host will be made for failover reasons.
# This option is actual only in dynamic connections mode. (integer value)
# from .Values.conf.oslo.messaging.zmq_failover_connections
{{ if not .Values.conf.oslo.messaging.zmq_failover_connections }}#{{ end }}zmq_failover_connections = {{ .Values.conf.oslo.messaging.zmq_failover_connections | default "2" }}

# Minimal port number for random ports range. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rpc_zmq_min_port
# from .Values.conf.oslo.messaging.rpc_zmq_min_port
{{ if not .Values.conf.oslo.messaging.rpc_zmq_min_port }}#{{ end }}rpc_zmq_min_port = {{ .Values.conf.oslo.messaging.rpc_zmq_min_port | default "49153" }}

# Maximal port number for random ports range. (integer value)
# Minimum value: 1
# Maximum value: 65536
# Deprecated group/name - [DEFAULT]/rpc_zmq_max_port
# from .Values.conf.oslo.messaging.rpc_zmq_max_port
{{ if not .Values.conf.oslo.messaging.rpc_zmq_max_port }}#{{ end }}rpc_zmq_max_port = {{ .Values.conf.oslo.messaging.rpc_zmq_max_port | default "65536" }}

# Number of retries to find free port number before fail with ZMQBindError.
# (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_port_retries
# from .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries
{{ if not .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries }}#{{ end }}rpc_zmq_bind_port_retries = {{ .Values.conf.oslo.messaging.rpc_zmq_bind_port_retries | default "100" }}

# Default serialization mechanism for serializing/deserializing
# outgoing/incoming messages (string value)
# Allowed values: json, msgpack
# Deprecated group/name - [DEFAULT]/rpc_zmq_serialization
# from .Values.conf.oslo.messaging.rpc_zmq_serialization
{{ if not .Values.conf.oslo.messaging.rpc_zmq_serialization }}#{{ end }}rpc_zmq_serialization = {{ .Values.conf.oslo.messaging.rpc_zmq_serialization | default "json" }}

# This option configures round-robin mode in zmq socket. True means not keeping
# a queue when server side disconnects. False means to keep queue and messages
# even if server is disconnected, when the server appears we send all
# accumulated messages to it. (boolean value)
# from .Values.conf.oslo.messaging.zmq_immediate
{{ if not .Values.conf.oslo.messaging.zmq_immediate }}#{{ end }}zmq_immediate = {{ .Values.conf.oslo.messaging.zmq_immediate | default "true" }}

# Enable/disable TCP keepalive (KA) mechanism. The default value of -1 (or any
# other negative value) means to skip any overrides and leave it to OS default;
# 0 and 1 (or any other positive value) mean to disable and enable the option
# respectively. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive }}#{{ end }}zmq_tcp_keepalive = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive | default "-1" }}

# The duration between two keepalive transmissions in idle condition. The unit
# is platform dependent, for example, seconds in Linux, milliseconds in Windows
# etc. The default value of -1 (or any other negative value and 0) means to
# skip any overrides and leave it to OS default. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle }}#{{ end }}zmq_tcp_keepalive_idle = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_idle | default "-1" }}

# The number of retransmissions to be carried out before declaring that remote
# end is not available. The default value of -1 (or any other negative value
# and 0) means to skip any overrides and leave it to OS default. (integer
# value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt }}#{{ end }}zmq_tcp_keepalive_cnt = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_cnt | default "-1" }}

# The duration between two successive keepalive retransmissions, if
# acknowledgement to the previous keepalive transmission is not received. The
# unit is platform dependent, for example, seconds in Linux, milliseconds in
# Windows etc. The default value of -1 (or any other negative value and 0)
# means to skip any overrides and leave it to OS default. (integer value)
# from .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl
{{ if not .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl }}#{{ end }}zmq_tcp_keepalive_intvl = {{ .Values.conf.oslo.messaging.zmq_tcp_keepalive_intvl | default "-1" }}

# Maximum number of (green) threads to work concurrently. (integer value)
# from .Values.conf.oslo.messaging.rpc_thread_pool_size
{{ if not .Values.conf.oslo.messaging.rpc_thread_pool_size }}#{{ end }}rpc_thread_pool_size = {{ .Values.conf.oslo.messaging.rpc_thread_pool_size | default "100" }}

# Expiration timeout in seconds of a sent/received message after which it is
# not tracked anymore by a client/server. (integer value)
# from .Values.conf.oslo.messaging.rpc_message_ttl
{{ if not .Values.conf.oslo.messaging.rpc_message_ttl }}#{{ end }}rpc_message_ttl = {{ .Values.conf.oslo.messaging.rpc_message_ttl | default "300" }}

# Wait for message acknowledgements from receivers. This mechanism works only
# via proxy without PUB/SUB. (boolean value)
# from .Values.conf.oslo.messaging.rpc_use_acks
{{ if not .Values.conf.oslo.messaging.rpc_use_acks }}#{{ end }}rpc_use_acks = {{ .Values.conf.oslo.messaging.rpc_use_acks | default "false" }}

# Number of seconds to wait for an ack from a cast/call. After each retry
# attempt this timeout is multiplied by some specified multiplier. (integer
# value)
# from .Values.conf.oslo.messaging.rpc_ack_timeout_base
{{ if not .Values.conf.oslo.messaging.rpc_ack_timeout_base }}#{{ end }}rpc_ack_timeout_base = {{ .Values.conf.oslo.messaging.rpc_ack_timeout_base | default "15" }}

# Number to multiply base ack timeout by after each retry attempt. (integer
# value)
# from .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier
{{ if not .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier }}#{{ end }}rpc_ack_timeout_multiplier = {{ .Values.conf.oslo.messaging.rpc_ack_timeout_multiplier | default "2" }}

# Default number of message sending attempts in case of any problems occurred:
# positive value N means at most N retries, 0 means no retries, None or -1 (or
# any other negative values) mean to retry forever. This option is used only if
# acknowledgments are enabled. (integer value)
# from .Values.conf.oslo.messaging.rpc_retry_attempts
{{ if not .Values.conf.oslo.messaging.rpc_retry_attempts }}#{{ end }}rpc_retry_attempts = {{ .Values.conf.oslo.messaging.rpc_retry_attempts | default "3" }}

# List of publisher hosts SubConsumer can subscribe on. This option has higher
# priority then the default publishers list taken from the matchmaker. (list
# value)
# from .Values.conf.oslo.messaging.subscribe_on
{{ if not .Values.conf.oslo.messaging.subscribe_on }}#{{ end }}subscribe_on = {{ .Values.conf.oslo.messaging.subscribe_on | default "" }}


[oslo_middleware]

#
# From oslo.middleware
#

# The maximum body size for each  request, in bytes. (integer value)
# Deprecated group/name - [DEFAULT]/osapi_max_request_body_size
# Deprecated group/name - [DEFAULT]/max_request_body_size
# from .Values.conf.oslo.middleware.max_request_body_size
{{ if not .Values.conf.oslo.middleware.max_request_body_size }}#{{ end }}max_request_body_size = {{ .Values.conf.oslo.middleware.max_request_body_size | default "114688" }}

# DEPRECATED: The HTTP Header that will be used to determine what the original
# request protocol scheme was, even if it was hidden by a SSL termination
# proxy. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .Values.conf.oslo.middleware.secure_proxy_ssl_header
{{ if not .Values.conf.oslo.middleware.secure_proxy_ssl_header }}#{{ end }}secure_proxy_ssl_header = {{ .Values.conf.oslo.middleware.secure_proxy_ssl_header | default "X-Forwarded-Proto" }}

# Whether the application is behind a proxy or not. This determines if the
# middleware should parse the headers or not. (boolean value)
# from .Values.conf.oslo.middleware.enable_proxy_headers_parsing
{{ if not .Values.conf.oslo.middleware.enable_proxy_headers_parsing }}#{{ end }}enable_proxy_headers_parsing = {{ .Values.conf.oslo.middleware.enable_proxy_headers_parsing | default "false" }}


[oslo_policy]

#
# From oslo.policy
#

# The file that defines policies. (string value)
# Deprecated group/name - [DEFAULT]/policy_file
# from .Values.conf.oslo.policy.policy_file
{{ if not .Values.conf.oslo.policy.policy_file }}#{{ end }}policy_file = {{ .Values.conf.oslo.policy.policy_file | default "policy.json" }}

# Default rule. Enforced when a requested rule is not found. (string value)
# Deprecated group/name - [DEFAULT]/policy_default_rule
# from .Values.conf.oslo.policy.policy_default_rule
{{ if not .Values.conf.oslo.policy.policy_default_rule }}#{{ end }}policy_default_rule = {{ .Values.conf.oslo.policy.policy_default_rule | default "default" }}

# Directories where policy configuration files are stored. They can be relative
# to any directory in the search path defined by the config_dir option, or
# absolute paths. The file defined by policy_file must exist for these
# directories to be searched.  Missing or empty directories are ignored. (multi
# valued)
# Deprecated group/name - [DEFAULT]/policy_dirs
# from .Values.conf.oslo.policy.policy_dirs
{{ if not .Values.conf.oslo.policy.policy_dirs }}#{{ end }}policy_dirs = {{ .Values.conf.oslo.policy.policy_dirs | default "policy.d" }}


[paste_deploy]

#
# From keystone
#

# Name of (or absolute path to) the Paste Deploy configuration file that
# composes middleware and the keystone application itself into actual WSGI
# entry points. See http://pythonpaste.org/deploy/ for additional documentation
# on the file's format. (string value)
# from .Values.conf.keystone.config_file
{{ if not .Values.conf.keystone.config_file }}#{{ end }}config_file = {{ .Values.conf.keystone.config_file | default "keystone-paste.ini" }}


[policy]

#
# From keystone
#

# Entry point for the policy backend driver in the `keystone.policy` namespace.
# Supplied drivers are `rules` (which does not support any CRUD operations for
# the v3 policy API) and `sql`. Typically, there is no reason to set this
# option unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Maximum number of entities that will be returned in a policy collection.
# (integer value)
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}


[profiler]

#
# From osprofiler
#

#
# Enables the profiling for all services on this node. Default value is False
# (fully disable the profiling feature).
#
# Possible values:
#
# * True: Enables the feature
# * False: Disables the feature. The profiling cannot be started via this
# project
# operations. If the profiling is triggered by another project, this project
# part
# will be empty.
#  (boolean value)
# Deprecated group/name - [profiler]/profiler_enabled
# from .Values.conf.osprofiler.enabled
{{ if not .Values.conf.osprofiler.enabled }}#{{ end }}enabled = {{ .Values.conf.osprofiler.enabled | default "false" }}

#
# Enables SQL requests profiling in services. Default value is False (SQL
# requests won't be traced).
#
# Possible values:
#
# * True: Enables SQL requests profiling. Each SQL query will be part of the
# trace and can the be analyzed by how much time was spent for that.
# * False: Disables SQL requests profiling. The spent time is only shown on a
# higher level of operations. Single SQL queries cannot be analyzed this
# way.
#  (boolean value)
# from .Values.conf.osprofiler.trace_sqlalchemy
{{ if not .Values.conf.osprofiler.trace_sqlalchemy }}#{{ end }}trace_sqlalchemy = {{ .Values.conf.osprofiler.trace_sqlalchemy | default "false" }}

#
# Secret key(s) to use for encrypting context data for performance profiling.
# This string value should have the following format:
# <key1>[,<key2>,...<keyn>],
# where each key is some random string. A user who triggers the profiling via
# the REST API has to set one of these keys in the headers of the REST API call
# to include profiling results of this node for this particular project.
#
# Both "enabled" flag and "hmac_keys" config options should be set to enable
# profiling. Also, to generate correct profiling information across all
# services
# at least one key needs to be consistent between OpenStack projects. This
# ensures it can be used from client side to generate the trace, containing
# information from all possible resources. (string value)
# from .Values.conf.osprofiler.hmac_keys
{{ if not .Values.conf.osprofiler.hmac_keys }}#{{ end }}hmac_keys = {{ .Values.conf.osprofiler.hmac_keys | default "SECRET_KEY" }}

#
# Connection string for a notifier backend. Default value is messaging:// which
# sets the notifier to oslo_messaging.
#
# Examples of possible values:
#
# * messaging://: use oslo_messaging driver for sending notifications.
# * mongodb://127.0.0.1:27017 : use mongodb driver for sending notifications.
# * elasticsearch://127.0.0.1:9200 : use elasticsearch driver for sending
# notifications.
#  (string value)
# from .Values.conf.osprofiler.connection_string
{{ if not .Values.conf.osprofiler.connection_string }}#{{ end }}connection_string = {{ .Values.conf.osprofiler.connection_string | default "messaging://" }}

#
# Document type for notification indexing in elasticsearch.
#  (string value)
# from .Values.conf.osprofiler.es_doc_type
{{ if not .Values.conf.osprofiler.es_doc_type }}#{{ end }}es_doc_type = {{ .Values.conf.osprofiler.es_doc_type | default "notification" }}

#
# This parameter is a time value parameter (for example: es_scroll_time=2m),
# indicating for how long the nodes that participate in the search will
# maintain
# relevant resources in order to continue and support it.
#  (string value)
# from .Values.conf.osprofiler.es_scroll_time
{{ if not .Values.conf.osprofiler.es_scroll_time }}#{{ end }}es_scroll_time = {{ .Values.conf.osprofiler.es_scroll_time | default "2m" }}

#
# Elasticsearch splits large requests in batches. This parameter defines
# maximum size of each batch (for example: es_scroll_size=10000).
#  (integer value)
# from .Values.conf.osprofiler.es_scroll_size
{{ if not .Values.conf.osprofiler.es_scroll_size }}#{{ end }}es_scroll_size = {{ .Values.conf.osprofiler.es_scroll_size | default "10000" }}

#
# Redissentinel provides a timeout option on the connections.
# This parameter defines that timeout (for example: socket_timeout=0.1).
#  (floating point value)
# from .Values.conf.osprofiler.socket_timeout
{{ if not .Values.conf.osprofiler.socket_timeout }}#{{ end }}socket_timeout = {{ .Values.conf.osprofiler.socket_timeout | default "0.1" }}

#
# Redissentinel uses a service name to identify a master redis service.
# This parameter defines the name (for example:
# sentinal_service_name=mymaster).
#  (string value)
# from .Values.conf.osprofiler.sentinel_service_name
{{ if not .Values.conf.osprofiler.sentinel_service_name }}#{{ end }}sentinel_service_name = {{ .Values.conf.osprofiler.sentinel_service_name | default "mymaster" }}


[resource]

#
# From keystone
#

# Entry point for the resource driver in the `keystone.resource` namespace.
# Only a `sql` driver is supplied by keystone. Unless you are writing
# proprietary drivers for keystone, you do not need to set this option. (string
# value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Toggle for resource caching. This has no effect unless global caching is
# enabled. (boolean value)
# Deprecated group/name - [assignment]/caching
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time to cache resource data in seconds. This has no effect unless global
# caching is enabled. (integer value)
# Deprecated group/name - [assignment]/cache_time
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "<None>" }}

# Maximum number of entities that will be returned in a resource collection.
# (integer value)
# Deprecated group/name - [assignment]/list_limit
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}

# Name of the domain that owns the `admin_project_name`. If left unset, then
# there is no admin project. `[resource] admin_project_name` must also be set
# to use this option. (string value)
# from .Values.conf.keystone.admin_project_domain_name
{{ if not .Values.conf.keystone.admin_project_domain_name }}#{{ end }}admin_project_domain_name = {{ .Values.conf.keystone.admin_project_domain_name | default "<None>" }}

# This is a special project which represents cloud-level administrator
# privileges across services. Tokens scoped to this project will contain a true
# `is_admin_project` attribute to indicate to policy systems that the role
# assignments on that specific project should apply equally across every
# project. If left unset, then there is no admin project, and thus no explicit
# means of cross-project role assignments. `[resource]
# admin_project_domain_name` must also be set to use this option. (string
# value)
# from .Values.conf.keystone.admin_project_name
{{ if not .Values.conf.keystone.admin_project_name }}#{{ end }}admin_project_name = {{ .Values.conf.keystone.admin_project_name | default "<None>" }}

# This controls whether the names of projects are restricted from containing
# URL-reserved characters. If set to `new`, attempts to create or update a
# project with a URL-unsafe name will fail. If set to `strict`, attempts to
# scope a token with a URL-unsafe project name will fail, thereby forcing all
# project names to be updated to be URL-safe. (string value)
# Allowed values: off, new, strict
# from .Values.conf.keystone.project_name_url_safe
{{ if not .Values.conf.keystone.project_name_url_safe }}#{{ end }}project_name_url_safe = {{ .Values.conf.keystone.project_name_url_safe | default "off" }}

# This controls whether the names of domains are restricted from containing
# URL-reserved characters. If set to `new`, attempts to create or update a
# domain with a URL-unsafe name will fail. If set to `strict`, attempts to
# scope a token with a URL-unsafe domain name will fail, thereby forcing all
# domain names to be updated to be URL-safe. (string value)
# Allowed values: off, new, strict
# from .Values.conf.keystone.domain_name_url_safe
{{ if not .Values.conf.keystone.domain_name_url_safe }}#{{ end }}domain_name_url_safe = {{ .Values.conf.keystone.domain_name_url_safe | default "off" }}


[revoke]

#
# From keystone
#

# Entry point for the token revocation backend driver in the `keystone.revoke`
# namespace. Keystone only provides a `sql` driver, so there is no reason to
# set this option unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# The number of seconds after a token has expired before a corresponding
# revocation event may be purged from the backend. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.expiration_buffer
{{ if not .Values.conf.keystone.expiration_buffer }}#{{ end }}expiration_buffer = {{ .Values.conf.keystone.expiration_buffer | default "1800" }}

# Toggle for revocation event caching. This has no effect unless global caching
# is enabled. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time to cache the revocation list and the revocation events (in seconds).
# This has no effect unless global and `[revoke] caching` are both enabled.
# (integer value)
# Deprecated group/name - [token]/revocation_cache_time
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "3600" }}


[role]

#
# From keystone
#

# Entry point for the role backend driver in the `keystone.role` namespace.
# Keystone only provides a `sql` driver, so there's no reason to change this
# unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "<None>" }}

# Toggle for role caching. This has no effect unless global caching is enabled.
# In a typical deployment, there is no reason to disable this. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# Time to cache role data, in seconds. This has no effect unless both global
# caching and `[role] caching` are enabled. (integer value)
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "<None>" }}

# Maximum number of entities that will be returned in a role collection. This
# may be useful to tune if you have a large number of discrete roles in your
# deployment. (integer value)
# from .Values.conf.keystone.list_limit
{{ if not .Values.conf.keystone.list_limit }}#{{ end }}list_limit = {{ .Values.conf.keystone.list_limit | default "<None>" }}


[saml]

#
# From keystone
#

# Determines the lifetime for any SAML assertions generated by keystone, using
# `NotOnOrAfter` attributes. (integer value)
# from .Values.conf.keystone.assertion_expiration_time
{{ if not .Values.conf.keystone.assertion_expiration_time }}#{{ end }}assertion_expiration_time = {{ .Values.conf.keystone.assertion_expiration_time | default "3600" }}

# Name of, or absolute path to, the binary to be used for XML signing. Although
# only the XML Security Library (`xmlsec1`) is supported, it may have a non-
# standard name or path on your system. If keystone cannot find the binary
# itself, you may need to install the appropriate package, use this option to
# specify an absolute path, or adjust keystone's PATH environment variable.
# (string value)
# from .Values.conf.keystone.xmlsec1_binary
{{ if not .Values.conf.keystone.xmlsec1_binary }}#{{ end }}xmlsec1_binary = {{ .Values.conf.keystone.xmlsec1_binary | default "xmlsec1" }}

# Absolute path to the public certificate file to use for SAML signing. The
# value cannot contain a comma (`,`). (string value)
# from .Values.conf.keystone.certfile
{{ if not .Values.conf.keystone.certfile }}#{{ end }}certfile = {{ .Values.conf.keystone.certfile | default "/etc/keystone/ssl/certs/signing_cert.pem" }}

# Absolute path to the private key file to use for SAML signing. The value
# cannot contain a comma (`,`). (string value)
# from .Values.conf.keystone.keyfile
{{ if not .Values.conf.keystone.keyfile }}#{{ end }}keyfile = {{ .Values.conf.keystone.keyfile | default "/etc/keystone/ssl/private/signing_key.pem" }}

# This is the unique entity identifier of the identity provider (keystone) to
# use when generating SAML assertions. This value is required to generate
# identity provider metadata and must be a URI (a URL is recommended). For
# example: `https://keystone.example.com/v3/OS-FEDERATION/saml2/idp`. (uri
# value)
# from .Values.conf.keystone.idp_entity_id
{{ if not .Values.conf.keystone.idp_entity_id }}#{{ end }}idp_entity_id = {{ .Values.conf.keystone.idp_entity_id | default "<None>" }}

# This is the single sign-on (SSO) service location of the identity provider
# which accepts HTTP POST requests. A value is required to generate identity
# provider metadata. For example: `https://keystone.example.com/v3/OS-
# FEDERATION/saml2/sso`. (uri value)
# from .Values.conf.keystone.idp_sso_endpoint
{{ if not .Values.conf.keystone.idp_sso_endpoint }}#{{ end }}idp_sso_endpoint = {{ .Values.conf.keystone.idp_sso_endpoint | default "<None>" }}

# This is the language used by the identity provider's organization. (string
# value)
# from .Values.conf.keystone.idp_lang
{{ if not .Values.conf.keystone.idp_lang }}#{{ end }}idp_lang = {{ .Values.conf.keystone.idp_lang | default "en" }}

# This is the name of the identity provider's organization. (string value)
# from .Values.conf.keystone.idp_organization_name
{{ if not .Values.conf.keystone.idp_organization_name }}#{{ end }}idp_organization_name = {{ .Values.conf.keystone.idp_organization_name | default "SAML Identity Provider" }}

# This is the name of the identity provider's organization to be displayed.
# (string value)
# from .Values.conf.keystone.idp_organization_display_name
{{ if not .Values.conf.keystone.idp_organization_display_name }}#{{ end }}idp_organization_display_name = {{ .Values.conf.keystone.idp_organization_display_name | default "OpenStack SAML Identity Provider" }}

# This is the URL of the identity provider's organization. The URL referenced
# here should be useful to humans. (uri value)
# from .Values.conf.keystone.idp_organization_url
{{ if not .Values.conf.keystone.idp_organization_url }}#{{ end }}idp_organization_url = {{ .Values.conf.keystone.idp_organization_url | default "https://example.com/" }}

# This is the company name of the identity provider's contact person. (string
# value)
# from .Values.conf.keystone.idp_contact_company
{{ if not .Values.conf.keystone.idp_contact_company }}#{{ end }}idp_contact_company = {{ .Values.conf.keystone.idp_contact_company | default "Example, Inc." }}

# This is the given name of the identity provider's contact person. (string
# value)
# from .Values.conf.keystone.idp_contact_name
{{ if not .Values.conf.keystone.idp_contact_name }}#{{ end }}idp_contact_name = {{ .Values.conf.keystone.idp_contact_name | default "SAML Identity Provider Support" }}

# This is the surname of the identity provider's contact person. (string value)
# from .Values.conf.keystone.idp_contact_surname
{{ if not .Values.conf.keystone.idp_contact_surname }}#{{ end }}idp_contact_surname = {{ .Values.conf.keystone.idp_contact_surname | default "Support" }}

# This is the email address of the identity provider's contact person. (string
# value)
# from .Values.conf.keystone.idp_contact_email
{{ if not .Values.conf.keystone.idp_contact_email }}#{{ end }}idp_contact_email = {{ .Values.conf.keystone.idp_contact_email | default "support@example.com" }}

# This is the telephone number of the identity provider's contact person.
# (string value)
# from .Values.conf.keystone.idp_contact_telephone
{{ if not .Values.conf.keystone.idp_contact_telephone }}#{{ end }}idp_contact_telephone = {{ .Values.conf.keystone.idp_contact_telephone | default "+1 800 555 0100" }}

# This is the type of contact that best describes the identity provider's
# contact person. (string value)
# Allowed values: technical, support, administrative, billing, other
# from .Values.conf.keystone.idp_contact_type
{{ if not .Values.conf.keystone.idp_contact_type }}#{{ end }}idp_contact_type = {{ .Values.conf.keystone.idp_contact_type | default "other" }}

# Absolute path to the identity provider metadata file. This file should be
# generated with the `keystone-manage saml_idp_metadata` command. There is
# typically no reason to change this value. (string value)
# from .Values.conf.keystone.idp_metadata_path
{{ if not .Values.conf.keystone.idp_metadata_path }}#{{ end }}idp_metadata_path = {{ .Values.conf.keystone.idp_metadata_path | default "/etc/keystone/saml2_idp_metadata.xml" }}

# The prefix of the RelayState SAML attribute to use when generating enhanced
# client and proxy (ECP) assertions. In a typical deployment, there is no
# reason to change this value. (string value)
# from .Values.conf.keystone.relay_state_prefix
{{ if not .Values.conf.keystone.relay_state_prefix }}#{{ end }}relay_state_prefix = {{ .Values.conf.keystone.relay_state_prefix | default "ss:mem:" }}


[security_compliance]

#
# From keystone
#

# The maximum number of days a user can go without authenticating before being
# considered "inactive" and automatically disabled (locked). This feature is
# disabled by default; set any value to enable it. This feature depends on the
# `sql` backend for the `[identity] driver`. When a user exceeds this threshold
# and is considered "inactive", the user's `enabled` attribute in the HTTP API
# may not match the value of the user's `enabled` column in the user table.
# (integer value)
# Minimum value: 1
# from .Values.conf.keystone.disable_user_account_days_inactive
{{ if not .Values.conf.keystone.disable_user_account_days_inactive }}#{{ end }}disable_user_account_days_inactive = {{ .Values.conf.keystone.disable_user_account_days_inactive | default "<None>" }}

# The maximum number of times that a user can fail to authenticate before the
# user account is locked for the number of seconds specified by
# `[security_compliance] lockout_duration`. This feature is disabled by
# default. If this feature is enabled and `[security_compliance]
# lockout_duration` is not set, then users may be locked out indefinitely until
# the user is explicitly enabled via the API. This feature depends on the `sql`
# backend for the `[identity] driver`. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.lockout_failure_attempts
{{ if not .Values.conf.keystone.lockout_failure_attempts }}#{{ end }}lockout_failure_attempts = {{ .Values.conf.keystone.lockout_failure_attempts | default "<None>" }}

# The number of seconds a user account will be locked when the maximum number
# of failed authentication attempts (as specified by `[security_compliance]
# lockout_failure_attempts`) is exceeded. Setting this option will have no
# effect unless you also set `[security_compliance] lockout_failure_attempts`
# to a non-zero value. This feature depends on the `sql` backend for the
# `[identity] driver`. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.lockout_duration
{{ if not .Values.conf.keystone.lockout_duration }}#{{ end }}lockout_duration = {{ .Values.conf.keystone.lockout_duration | default "1800" }}

# The number of days for which a password will be considered valid before
# requiring it to be changed. This feature is disabled by default. If enabled,
# new password changes will have an expiration date, however existing passwords
# would not be impacted. This feature depends on the `sql` backend for the
# `[identity] driver`. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.password_expires_days
{{ if not .Values.conf.keystone.password_expires_days }}#{{ end }}password_expires_days = {{ .Values.conf.keystone.password_expires_days | default "<None>" }}

# DEPRECATED: Comma separated list of user IDs to be ignored when checking if a
# password is expired. Passwords for users in this list will not expire. This
# feature will only be enabled if `[security_compliance] password_expires_days`
# is set. (list value)
# This option is deprecated for removal since O.
# Its value may be silently ignored in the future.
# Reason: Functionality added as a per-user option "ignore_password_expiry" in
# Ocata. Each user that should ignore password expiry should have the value set
# to "true" in the user's `options` attribute (e.g.
# `user['options']['ignore_password_expiry'] = True`) with an "update_user"
# call. This avoids the need to restart keystone to adjust the users that
# ignore password expiry. This option will be removed in the Pike release.
# from .Values.conf.keystone.password_expires_ignore_user_ids
{{ if not .Values.conf.keystone.password_expires_ignore_user_ids }}#{{ end }}password_expires_ignore_user_ids = {{ .Values.conf.keystone.password_expires_ignore_user_ids | default "" }}

# This controls the number of previous user password iterations to keep in
# history, in order to enforce that newly created passwords are unique. Setting
# the value to one (the default) disables this feature. Thus, to enable this
# feature, values must be greater than 1. This feature depends on the `sql`
# backend for the `[identity] driver`. (integer value)
# Minimum value: 1
# from .Values.conf.keystone.unique_last_password_count
{{ if not .Values.conf.keystone.unique_last_password_count }}#{{ end }}unique_last_password_count = {{ .Values.conf.keystone.unique_last_password_count | default "1" }}

# The number of days that a password must be used before the user can change
# it. This prevents users from changing their passwords immediately in order to
# wipe out their password history and reuse an old password. This feature does
# not prevent administrators from manually resetting passwords. It is disabled
# by default and allows for immediate password changes. This feature depends on
# the `sql` backend for the `[identity] driver`. Note: If
# `[security_compliance] password_expires_days` is set, then the value for this
# option should be less than the `password_expires_days`. (integer value)
# Minimum value: 0
# from .Values.conf.keystone.minimum_password_age
{{ if not .Values.conf.keystone.minimum_password_age }}#{{ end }}minimum_password_age = {{ .Values.conf.keystone.minimum_password_age | default "0" }}

# The regular expression used to validate password strength requirements. By
# default, the regular expression will match any password. The following is an
# example of a pattern which requires at least 1 letter, 1 digit, and have a
# minimum length of 7 characters: ^(?=.*\d)(?=.*[a-zA-Z]).{7,}$ This feature
# depends on the `sql` backend for the `[identity] driver`. (string value)
# from .Values.conf.keystone.password_regex
{{ if not .Values.conf.keystone.password_regex }}#{{ end }}password_regex = {{ .Values.conf.keystone.password_regex | default "<None>" }}

# Describe your password regular expression here in language for humans. If a
# password fails to match the regular expression, the contents of this
# configuration variable will be returned to users to explain why their
# requested password was insufficient. (string value)
# from .Values.conf.keystone.password_regex_description
{{ if not .Values.conf.keystone.password_regex_description }}#{{ end }}password_regex_description = {{ .Values.conf.keystone.password_regex_description | default "<None>" }}

# Enabling this option requires users to change their password when the user is
# created, or upon administrative reset. Before accessing any services,
# affected users will have to change their password. To ignore this requirement
# for specific users, such as service users, set the `options` attribute
# `ignore_change_password_upon_first_use` to `True` for the desired user via
# the update user API. This feature is disabled by default. This feature is
# only applicable with the `sql` backend for the `[identity] driver`. (boolean
# value)
# from .Values.conf.keystone.change_password_upon_first_use
{{ if not .Values.conf.keystone.change_password_upon_first_use }}#{{ end }}change_password_upon_first_use = {{ .Values.conf.keystone.change_password_upon_first_use | default "false" }}


[shadow_users]

#
# From keystone
#

# Entry point for the shadow users backend driver in the
# `keystone.identity.shadow_users` namespace. This driver is used for
# persisting local user references to externally-managed identities (via
# federation, LDAP, etc). Keystone only provides a `sql` driver, so there is no
# reason to change this option unless you are providing a custom entry point.
# (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}


[signing]

#
# From keystone
#

# Absolute path to the public certificate file to use for signing responses to
# revocation lists requests. Set this together with `[signing] keyfile`. For
# non-production environments, you may be interested in using `keystone-manage
# pki_setup` to generate self-signed certificates. (string value)
# from .Values.conf.keystone.certfile
{{ if not .Values.conf.keystone.certfile }}#{{ end }}certfile = {{ .Values.conf.keystone.certfile | default "/etc/keystone/ssl/certs/signing_cert.pem" }}

# Absolute path to the private key file to use for signing responses to
# revocation lists requests. Set this together with `[signing] certfile`.
# (string value)
# from .Values.conf.keystone.keyfile
{{ if not .Values.conf.keystone.keyfile }}#{{ end }}keyfile = {{ .Values.conf.keystone.keyfile | default "/etc/keystone/ssl/private/signing_key.pem" }}

# Absolute path to the public certificate authority (CA) file to use when
# creating self-signed certificates with `keystone-manage pki_setup`. Set this
# together with `[signing] ca_key`. There is no reason to set this option
# unless you are requesting revocation lists in a non-production environment.
# Use a `[signing] certfile` issued from a trusted certificate authority
# instead. (string value)
# from .Values.conf.keystone.ca_certs
{{ if not .Values.conf.keystone.ca_certs }}#{{ end }}ca_certs = {{ .Values.conf.keystone.ca_certs | default "/etc/keystone/ssl/certs/ca.pem" }}

# Absolute path to the private certificate authority (CA) key file to use when
# creating self-signed certificates with `keystone-manage pki_setup`. Set this
# together with `[signing] ca_certs`. There is no reason to set this option
# unless you are requesting revocation lists in a non-production environment.
# Use a `[signing] certfile` issued from a trusted certificate authority
# instead. (string value)
# from .Values.conf.keystone.ca_key
{{ if not .Values.conf.keystone.ca_key }}#{{ end }}ca_key = {{ .Values.conf.keystone.ca_key | default "/etc/keystone/ssl/private/cakey.pem" }}

# Key size (in bits) to use when generating a self-signed token signing
# certificate. There is no reason to set this option unless you are requesting
# revocation lists in a non-production environment. Use a `[signing] certfile`
# issued from a trusted certificate authority instead. (integer value)
# Minimum value: 1024
# from .Values.conf.keystone.key_size
{{ if not .Values.conf.keystone.key_size }}#{{ end }}key_size = {{ .Values.conf.keystone.key_size | default "2048" }}

# The validity period (in days) to use when generating a self-signed token
# signing certificate. There is no reason to set this option unless you are
# requesting revocation lists in a non-production environment. Use a `[signing]
# certfile` issued from a trusted certificate authority instead. (integer
# value)
# from .Values.conf.keystone.valid_days
{{ if not .Values.conf.keystone.valid_days }}#{{ end }}valid_days = {{ .Values.conf.keystone.valid_days | default "3650" }}

# The certificate subject to use when generating a self-signed token signing
# certificate. There is no reason to set this option unless you are requesting
# revocation lists in a non-production environment. Use a `[signing] certfile`
# issued from a trusted certificate authority instead. (string value)
# from .Values.conf.keystone.cert_subject
{{ if not .Values.conf.keystone.cert_subject }}#{{ end }}cert_subject = {{ .Values.conf.keystone.cert_subject | default "/C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com" }}


[token]

#
# From keystone
#

# This is a list of external authentication mechanisms which should add token
# binding metadata to tokens, such as `kerberos` or `x509`. Binding metadata is
# enforced according to the `[token] enforce_token_bind` option. (list value)
# from .Values.conf.keystone.bind
{{ if not .Values.conf.keystone.bind }}#{{ end }}bind = {{ .Values.conf.keystone.bind | default "" }}

# This controls the token binding enforcement policy on tokens presented to
# keystone with token binding metadata (as specified by the `[token] bind`
# option). `disabled` completely bypasses token binding validation.
# `permissive` and `strict` do not require tokens to have binding metadata (but
# will validate it if present), whereas `required` will always demand tokens to
# having binding metadata. `permissive` will allow unsupported binding metadata
# to pass through without validation (usually to be validated at another time
# by another component), whereas `strict` and `required` will demand that the
# included binding metadata be supported by keystone. (string value)
# Allowed values: disabled, permissive, strict, required
# from .Values.conf.keystone.enforce_token_bind
{{ if not .Values.conf.keystone.enforce_token_bind }}#{{ end }}enforce_token_bind = {{ .Values.conf.keystone.enforce_token_bind | default "permissive" }}

# The amount of time that a token should remain valid (in seconds). Drastically
# reducing this value may break "long-running" operations that involve multiple
# services to coordinate together, and will force users to authenticate with
# keystone more frequently. Drastically increasing this value will increase
# load on the `[token] driver`, as more tokens will be simultaneously valid.
# Keystone tokens are also bearer tokens, so a shorter duration will also
# reduce the potential security impact of a compromised token. (integer value)
# Minimum value: 0
# Maximum value: 9223372036854775807
# from .Values.conf.keystone.expiration
{{ if not .Values.conf.keystone.expiration }}#{{ end }}expiration = {{ .Values.conf.keystone.expiration | default "3600" }}

# Entry point for the token provider in the `keystone.token.provider`
# namespace. The token provider controls the token construction, validation,
# and revocation operations. Keystone includes `fernet` and `uuid` token
# providers. `uuid` tokens must be persisted (using the backend specified in
# the `[token] driver` option), but do not require any extra configuration or
# setup. `fernet` tokens do not need to be persisted at all, but require that
# you run `keystone-manage fernet_setup` (also see the `keystone-manage
# fernet_rotate` command). (string value)
# from .Values.conf.keystone.provider
{{ if not .Values.conf.keystone.provider }}#{{ end }}provider = {{ .Values.conf.keystone.provider | default "fernet" }}

# Entry point for the token persistence backend driver in the
# `keystone.token.persistence` namespace. Keystone provides the `sql` driver.
# The `sql` option (default) depends on the options in your `[database]`
# section. If you're using the `fernet` `[token] provider`, this backend will
# not be utilized to persist tokens at all. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}

# Toggle for caching token creation and validation data. This has no effect
# unless global caching is enabled. (boolean value)
# from .Values.conf.keystone.caching
{{ if not .Values.conf.keystone.caching }}#{{ end }}caching = {{ .Values.conf.keystone.caching | default "true" }}

# The number of seconds to cache token creation and validation data. This has
# no effect unless both global and `[token] caching` are enabled. (integer
# value)
# Minimum value: 0
# Maximum value: 9223372036854775807
# from .Values.conf.keystone.cache_time
{{ if not .Values.conf.keystone.cache_time }}#{{ end }}cache_time = {{ .Values.conf.keystone.cache_time | default "<None>" }}

# This toggles support for revoking individual tokens by the token identifier
# and thus various token enumeration operations (such as listing all tokens
# issued to a specific user). These operations are used to determine the list
# of tokens to consider revoked. Do not disable this option if you're using the
# `kvs` `[revoke] driver`. (boolean value)
# from .Values.conf.keystone.revoke_by_id
{{ if not .Values.conf.keystone.revoke_by_id }}#{{ end }}revoke_by_id = {{ .Values.conf.keystone.revoke_by_id | default "true" }}

# This toggles whether scoped tokens may be be re-scoped to a new project or
# domain, thereby preventing users from exchanging a scoped token (including
# those with a default project scope) for any other token. This forces users to
# either authenticate for unscoped tokens (and later exchange that unscoped
# token for tokens with a more specific scope) or to provide their credentials
# in every request for a scoped token to avoid re-scoping altogether. (boolean
# value)
# from .Values.conf.keystone.allow_rescope_scoped_token
{{ if not .Values.conf.keystone.allow_rescope_scoped_token }}#{{ end }}allow_rescope_scoped_token = {{ .Values.conf.keystone.allow_rescope_scoped_token | default "true" }}

# This controls whether roles should be included with tokens that are not
# directly assigned to the token's scope, but are instead linked implicitly to
# other role assignments. (boolean value)
# from .Values.conf.keystone.infer_roles
{{ if not .Values.conf.keystone.infer_roles }}#{{ end }}infer_roles = {{ .Values.conf.keystone.infer_roles | default "true" }}

# Enable storing issued token data to token validation cache so that first
# token validation doesn't actually cause full validation cycle. This option
# has no effect unless global caching and token caching are enabled. (boolean
# value)
# from .Values.conf.keystone.cache_on_issue
{{ if not .Values.conf.keystone.cache_on_issue }}#{{ end }}cache_on_issue = {{ .Values.conf.keystone.cache_on_issue | default "true" }}

# This controls the number of seconds that a token can be retrieved for beyond
# the built-in expiry time. This allows long running operations to succeed.
# Defaults to two days. (integer value)
# from .Values.conf.keystone.allow_expired_window
{{ if not .Values.conf.keystone.allow_expired_window }}#{{ end }}allow_expired_window = {{ .Values.conf.keystone.allow_expired_window | default "172800" }}


[tokenless_auth]

#
# From keystone
#

# The list of distinguished names which identify trusted issuers of client
# certificates allowed to use X.509 tokenless authorization. If the option is
# absent then no certificates will be allowed. The format for the values of a
# distinguished name (DN) must be separated by a comma and contain no spaces.
# Furthermore, because an individual DN may contain commas, this configuration
# option may be repeated multiple times to represent multiple values. For
# example, keystone.conf would include two consecutive lines in order to trust
# two different DNs, such as `trusted_issuer = CN=john,OU=keystone,O=openstack`
# and `trusted_issuer = CN=mary,OU=eng,O=abc`. (multi valued)
# from .Values.conf.keystone.trusted_issuer
{{ if not .Values.conf.keystone.trusted_issuer }}#{{ end }}trusted_issuer = {{ .Values.conf.keystone.trusted_issuer | default "" }}

# The federated protocol ID used to represent X.509 tokenless authorization.
# This is used in combination with the value of `[tokenless_auth]
# issuer_attribute` to find a corresponding federated mapping. In a typical
# deployment, there is no reason to change this value. (string value)
# from .Values.conf.keystone.protocol
{{ if not .Values.conf.keystone.protocol }}#{{ end }}protocol = {{ .Values.conf.keystone.protocol | default "x509" }}

# The name of the WSGI environment variable used to pass the issuer of the
# client certificate to keystone. This attribute is used as an identity
# provider ID for the X.509 tokenless authorization along with the protocol to
# look up its corresponding mapping. In a typical deployment, there is no
# reason to change this value. (string value)
# from .Values.conf.keystone.issuer_attribute
{{ if not .Values.conf.keystone.issuer_attribute }}#{{ end }}issuer_attribute = {{ .Values.conf.keystone.issuer_attribute | default "SSL_CLIENT_I_DN" }}


[trust]

#
# From keystone
#

# Delegation and impersonation features using trusts can be optionally
# disabled. (boolean value)
# from .Values.conf.keystone.enabled
{{ if not .Values.conf.keystone.enabled }}#{{ end }}enabled = {{ .Values.conf.keystone.enabled | default "true" }}

# Allows authorization to be redelegated from one user to another, effectively
# chaining trusts together. When disabled, the `remaining_uses` attribute of a
# trust is constrained to be zero. (boolean value)
# from .Values.conf.keystone.allow_redelegation
{{ if not .Values.conf.keystone.allow_redelegation }}#{{ end }}allow_redelegation = {{ .Values.conf.keystone.allow_redelegation | default "false" }}

# Maximum number of times that authorization can be redelegated from one user
# to another in a chain of trusts. This number may be reduced further for a
# specific trust. (integer value)
# from .Values.conf.keystone.max_redelegation_count
{{ if not .Values.conf.keystone.max_redelegation_count }}#{{ end }}max_redelegation_count = {{ .Values.conf.keystone.max_redelegation_count | default "3" }}

# Entry point for the trust backend driver in the `keystone.trust` namespace.
# Keystone only provides a `sql` driver, so there is no reason to change this
# unless you are providing a custom entry point. (string value)
# from .Values.conf.keystone.driver
{{ if not .Values.conf.keystone.driver }}#{{ end }}driver = {{ .Values.conf.keystone.driver | default "sql" }}
