%% ====================================================================
%% @author Gavin M. Roy <gavinmroy@gmail.com>
%% @copyright 2016-2018, Gavin M. Roy
%% @doc httpc_aws supervisor
%% @end
%% ====================================================================
-module(httpc_aws_sup).

-behaviour(supervisor).

-export([start_link/0,
         init/1]).

-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5, Type, [I]}).

start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  {ok, {{one_for_one, 5, 10}, [?CHILD(httpc_aws, worker)]}}.
