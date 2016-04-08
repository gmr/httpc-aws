%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016, Gavin M. Roy
%% @headerfile
%% @private
%% @doc httpc_aws client library constants and records
%% @end
%% ====================================================================

-define(ALGORITHM, "AWS4-HMAC-SHA256").
-define(MIME_AWS_JSON, "application/x-amz-json-1.0").
-define(SCHEME, https).

-define(DEFAULT_PROFILE, "default").
-define(INSTANCE_AZ, ["placement", "availability-zone"]).
-define(INSTANCE_HOST, "169.254.169.254").
-define(INSTANCE_CONNECT_TIMEOUT, 100).
-define(INSTANCE_CREDENTIALS, ["iam", "security-credentials"]).
-define(INSTANCE_METADATA_BASE, ["latest", "meta-data"]).

-type scheme() :: string() | undefined.
-type username() :: string() | undefined.
-type password() :: string() | undefined.
-type host() :: string().
-type tcp_port() :: integer() | undefined.
-type path() :: string() | undefined.
-type query() :: [tuple() | string()] | [] | undefined.
-type fragment() :: string() | undefined.

-type access_key() :: nonempty_string().
-type secret_access_key() :: nonempty_string().
-type expiration() :: nonempty_string().
-type security_token() :: nonempty_string().

-record(state, {access_key :: undefined | access_key(),
                secret_access_key :: undefined | secret_access_key(),
                expiration :: undefined | expiration(),
                security_token :: undefined | security_token()}).
-type state() :: #state{}.

