%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016-2018, Gavin M. Roy
%% @doc httpc_aws application startup
%% @end
%% ====================================================================
-module(httpc_aws_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
  httpc_aws_sup:start_link().

stop(_State) ->
  ok.
