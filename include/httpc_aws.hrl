%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016, Gavin M. Roy
%% @headerfile
%% @private
%% @doc httpc_aws client library constants and records
%% @end
%% ====================================================================

-include_lib("ssl/src/ssl_api.hrl").

-define(MIME_AWS_JSON, "application/x-amz-json-1.0").
-define(SCHEME, https).

-define(DEFAULT_PROFILE, "default").
-define(DEFAULT_REGION, "us-east-1").

-define(INSTANCE_AZ, ["placement", "availability-zone"]).
-define(INSTANCE_HOST, "169.254.169.254").
-define(INSTANCE_CONNECT_TIMEOUT, 100).
-define(INSTANCE_CREDENTIALS, ["iam", "security-credentials"]).
-define(INSTANCE_METADATA_BASE, ["latest", "meta-data"]).

-type region() :: nonempty_string().

-type access_key() :: nonempty_string().
-type secret_access_key() :: nonempty_string().
-type expiration() :: calendar:datetime() | undefined.
-type security_token() :: nonempty_string() | undefined.

-type sc_ok() :: {ok,
                  access_key(),
                  secret_access_key(),
                  expiration(),
                  security_token()}.
-type sc_error() :: {error, Reason :: atom()}.
-type security_credentials() :: sc_ok() | sc_error().

-record(state, {access_key :: access_key() | undefined,
                secret_access_key :: secret_access_key() | undefined,
                expiration :: expiration(),
                security_token :: security_token(),
                region :: region() | undefined,
                error :: atom() | string() | undefined}).
-type state() :: #state{}.

-type scheme() :: atom().
-type username() :: string().
-type password() :: string().
-type host() :: string().
-type tcp_port() :: integer().
-type query_args() :: [tuple() | string()].
-type fragment() :: string().

-type userinfo() :: {undefined | username(),
                     undefined | password()}.

-type authority() :: {undefined | userinfo(),
                      host(),
                      undefined | tcp_port()}.
-record(uri, {scheme :: undefined | scheme(),
              authority :: authority(),
              path :: undefined | path(),
              query :: undefined | query_args(),
              fragment :: undefined | fragment()}).

-type method() :: head | get | put | post | trace | options | delete | patch.
-type http_version() :: string().
-type status_code() :: integer().
-type reason_phrase() :: string().
-type status_line() :: {http_version(), status_code(), reason_phrase()}.
-type field() :: string().
-type value() :: string().
-type headers() :: [{Field :: field(), Value :: value()}].
-type body() :: string() | binary().

-type ssl_options() :: [ssl_option()].

-type http_option() :: {timeout, timeout()} |
                       {connect_timeout, timeout()} |
                       {ssl, ssl_options()} |
                       {essl, ssl_options()} |
                       {autoredirect, boolean()} |
                       {proxy_auth, {User :: string(), Password :: string()}} |
                       {version, http_version()} |
                       {relaxed, boolean()} |
                       {url_encode, boolean()}.
-type http_options() :: [http_option()].


-record(request, {access_key :: access_key(),
                  secret_access_key :: secret_access_key(),
                  security_token :: security_token(),
                  service :: string(),
                  region = "us-east-1" :: string(),
                  method = get :: method(),
                  headers = [] :: headers(),
                  uri :: string(),
                  body = "" :: body()}).
-type request() :: #request{}.

-type httpc_result() :: {status_line(), headers(), body()} |
                        {status_code(), body()} |
                        {error, term()}.

-type result_ok() :: {ok, {ResponseHeaders :: headers(), Response :: list()}}.
-type result_error() :: {error, Message :: reason_phrase(), {ResponseHeaders :: headers(), Response :: list()} | undefined} |
                        {error, credentials, Reason :: string()}.
-type result() :: result_ok() | result_error().
