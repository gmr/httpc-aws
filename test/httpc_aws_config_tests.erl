-module(httpc_aws_config_tests).

-include_lib("eunit/include/eunit.hrl").

-include("httpc_aws.hrl").


config_file_test_() ->
  [
    {"from environment variable", fun() ->
      os:putenv("AWS_CONFIG_FILE", "/etc/aws/config"),
      ?assertEqual("/etc/aws/config", httpc_aws_config:config_file())
     end},
    {"default without environment variable", fun() ->
      os:unsetenv("AWS_CONFIG_FILE"),
      os:putenv("HOME", "/home/gavinr"),
      ?assertEqual("/home/gavinr/.aws/config",
                   httpc_aws_config:config_file())
     end}
  ].

config_file_data_test_() ->
  [
    {"successfully parses ini", fun() ->
      setup_test_config_env_var(),
      Expectation = [
        {"default",
          [{aws_access_key_id, "default-key"},
           {aws_secret_access_key, "default-access-key"},
           {region, "us-east-4"}]},
        {"profile testing",
          [{aws_access_key_id, "foo1"},
           {aws_secret_access_key, "bar2"},
           {s3, [{max_concurrent_requests, 10},
                 {max_queue_size, 1000}]},
           {region, "us-west-5"}]},
        {"profile no-region",
          [{aws_access_key_id, "foo2"},
           {aws_secret_access_key, "bar3"}]},
        {"profile only-key",
          [{aws_access_key_id, "foo3"}]},
        {"profile only-secret",
          [{aws_secret_access_key, "foo4"}]},
        {"profile bad-entry",
          [{aws_secret_access, "foo5"}]}
      ],
      ?assertEqual(Expectation,
                   httpc_aws_config:config_file_data())
     end},
    {"file does not exist", fun() ->
      ?assertEqual({error, enoent},
                   httpc_aws_config:ini_file_data(filename:join([filename:absname("."), "bad_path"]), false))
      end
    },
    {"file exists but path is invalid", fun() ->
      ?assertEqual({error, enoent},
                   httpc_aws_config:ini_file_data(filename:join([filename:absname("."), "bad_path"]), true))
      end
    }
  ].



credentials_file_test_() ->
  [
    {"from environment variable", fun() ->
      os:putenv("AWS_SHARED_CREDENTIALS_FILE", "/etc/aws/credentials"),
      ?assertEqual("/etc/aws/credentials", httpc_aws_config:credentials_file())
     end},
    {"default without environment variable", fun() ->
      os:unsetenv("AWS_SHARED_CREDENTIALS_FILE"),
      os:putenv("HOME", "/home/gavinr"),
      ?assertEqual("/home/gavinr/.aws/credentials",
                   httpc_aws_config:credentials_file())
     end}
  ].


credentials_test_() ->
  {
    foreach,
    fun () ->
      meck:new(httpc),
      reset_environment(),
      [httpc]
    end,
    fun meck:unload/1,
    [
      {"from environment variables", fun() ->
        os:putenv("AWS_ACCESS_KEY_ID", "Sésame"),
        os:putenv("AWS_SECRET_ACCESS_KEY", "ouvre-toi"),
        ?assertEqual({ok, "Sésame", "ouvre-toi", undefined, undefined},
                     httpc_aws_config:credentials())
       end},
      {"from config file with default profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, "default-key", "default-access-key", undefined, undefined},
                     httpc_aws_config:credentials())
       end},
      {"with missing environment variable", fun() ->
        os:putenv("AWS_ACCESS_KEY_ID", "Sésame"),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials())
       end},
      {"from config file with default profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, "default-key", "default-access-key", undefined, undefined},
                     httpc_aws_config:credentials())
       end},
      {"from config file with profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, "foo1", "bar2", undefined, undefined},
                     httpc_aws_config:credentials("testing"))
       end},
      {"from config file with bad profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials("bad-profile-name"))
       end},
      {"from credentials file with default profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({ok, "foo1", "bar1", undefined, undefined},
                     httpc_aws_config:credentials())
       end},
      {"from credentials file with profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({ok, "foo2", "bar2", undefined, undefined},
                     httpc_aws_config:credentials("development"))
       end},
      {"from credentials file with bad profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials("bad-profile-name"))
       end},
      {"from credentials file with only the key in profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials("only-key"))
       end},
      {"from credentials file with only the value in profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials("only-value"))
       end},
      {"from credentials file with missing keys in profile", fun() ->
        setup_test_credentials_env_var(),
        ?assertEqual({error, undefined},
                     httpc_aws_config:credentials("bad-entry"))
       end},
      {"from instance metadata service", fun() ->
        CredsBody = "{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"2016-03-31T21:51:49Z\",\n  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"ASIAIMAFAKEACCESSKEY\",\n  \"SecretAccessKey\" : \"2+t64tZZVaz0yp0x1G23ZRYn+FAKEyVALUEs/4qh\",\n  \"Token\" : \"FAKE//////////wEAK/TOKEN/VALUE=\",\n  \"Expiration\" : \"2016-04-01T04:13:28Z\"\n}",
        meck:sequence(httpc, request, 4,
                      [{ok, {{protocol, 200, message}, headers, "Bob"}},
                       {ok, {{protocol, 200, message}, headers, CredsBody}}]),
        Expectation = {ok, "ASIAIMAFAKEACCESSKEY", "2+t64tZZVaz0yp0x1G23ZRYn+FAKEyVALUEs/4qh",
                       {{2016,4,1},{4,13,28}}, "FAKE//////////wEAK/TOKEN/VALUE="},
        ?assertEqual(Expectation, httpc_aws_config:credentials())
       end
      },
      {"with instance metadata service role error", fun() ->
        meck:expect(httpc, request, 4, {error, timeout}),
        ?assertEqual({error, undefined}, httpc_aws_config:credentials())
       end
      },
      {"with instance metadata service role http error", fun() ->
        meck:expect(httpc, request, 4,
                    {ok, {{protocol, 500, message}, headers, "Internal Server Error"}}),
        ?assertEqual({error, undefined}, httpc_aws_config:credentials())
       end
      },
      {"with instance metadata service credentials error", fun() ->
        meck:sequence(httpc, request, 4,
                      [{ok, {{protocol, 200, message}, headers, "Bob"}},
                       {error, timeout}]),
        ?assertEqual({error, undefined}, httpc_aws_config:credentials())
       end
      },
      {"with instance metadata service credentials not found", fun() ->
        meck:sequence(httpc, request, 4,
                      [{ok, {{protocol, 200, message}, headers, "Bob"}},
                       {ok, {{protocol, 404, message}, headers, "File Not Found"}}]),
        ?assertEqual({error, undefined}, httpc_aws_config:credentials())
       end
      }

    ]}.


home_path_test_() ->
  [
    {"with HOME", fun() ->
        os:putenv("HOME", "/home/gavinr"),
        ?assertEqual("/home/gavinr",
                     httpc_aws_config:home_path())
     end},
    {"without HOME", fun() ->
      os:unsetenv("HOME"),
      ?assertEqual(filename:absname("."),
                   httpc_aws_config:home_path())
     end}
  ].


ini_format_key_test_() ->
  [
    {"when value is list", fun() ->
      ?assertEqual(test_key, httpc_aws_config:ini_format_key("test_key"))
     end},
    {"when value is binary", fun() ->
      ?assertEqual({error, type}, httpc_aws_config:ini_format_key(<<"test_key">>))
     end}
  ].


maybe_convert_number_test_() ->
  [
    {"when string contains an integer", fun() ->
      ?assertEqual(123, httpc_aws_config:maybe_convert_number("123"))
     end},
    {"when string contains a float", fun() ->
      ?assertEqual(123.456, httpc_aws_config:maybe_convert_number("123.456"))
     end},
    {"when string does not contain a number", fun() ->
     ?assertEqual("hello, world", httpc_aws_config:maybe_convert_number("hello, world"))
     end}
  ].


parse_iso8601_test_() ->
  [
    {"parse test", fun() ->
      Value = "2016-05-19T18:25:23Z",
      Expectation = {{2016,5,19},{18,25,23}},
      ?assertEqual(Expectation, httpc_aws_config:parse_iso8601_timestamp(Value))
    end}
  ].


profile_test_() ->
  [
    {"from environment variable", fun() ->
      os:putenv("AWS_DEFAULT_PROFILE", "httpc-aws test"),
      ?assertEqual("httpc-aws test", httpc_aws_config:profile())
     end},
    {"default without environment variable", fun() ->
      os:unsetenv("AWS_DEFAULT_PROFILE"),
      ?assertEqual("default", httpc_aws_config:profile())
     end}
  ].


read_file_test_() ->
  [
    {"file does not exist", fun() ->
      ?assertEqual({error, enoent}, httpc_aws_config:read_file(filename:join([filename:absname("."), "bad_path"])))
     end},
    {"file handle is closed", fun() ->
      {MegaSecs, Secs, MicroSecs} = erlang:timestamp(),
      Name = lists:flatten(io_lib:format("~p-~p-~p.tmp", [MegaSecs, Secs, MicroSecs])),
      {ok, Handle} = file:open(Name, [write]),
      file:close(Handle),
      ?assertEqual({error,terminated}, httpc_aws_config:read_file(Handle, [])),
      file:delete(Name)
     end}
  ].


region_test_() ->
  {
    foreach,
    fun () ->
      meck:new(httpc),
      reset_environment(),
      [httpc]
    end,
    fun meck:unload/1,
    [
      {"with environment variable", fun() ->
        os:putenv("AWS_DEFAULT_REGION", "us-west-1"),
        ?assertEqual({ok, "us-west-1"}, httpc_aws_config:region())
       end},
      {"with config file and specified profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, "us-west-5"}, httpc_aws_config:region("testing"))
       end},
      {"with config file using default profile", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, "us-east-4"}, httpc_aws_config:region())
       end},
      {"missing profile in config", fun() ->
        setup_test_config_env_var(),
        ?assertEqual({ok, ?DEFAULT_REGION}, httpc_aws_config:region("no-region"))
       end},
      {"from instance metadata service", fun() ->
        meck:expect(httpc, request, 4,
                    {ok, {{protocol, 200, message}, headers, "us-west-1a"}}),
        ?assertEqual({ok, "us-west-1"}, httpc_aws_config:region())
       end},
      {"full lookup failure", fun() ->
        ?assertEqual({ok, ?DEFAULT_REGION}, httpc_aws_config:region())
       end},
      {"http error failure", fun() ->
        meck:expect(httpc, request, 4,
                    {ok, {{protocol, 500, message}, headers, "Internal Server Error"}}),
        ?assertEqual({ok, ?DEFAULT_REGION}, httpc_aws_config:region())
       end}
    ]}.


reset_environment() ->
  os:unsetenv("AWS_ACCESS_KEY_ID"),
  os:unsetenv("AWS_DEFAULT_REGION"),
  os:unsetenv("AWS_SECRET_ACCESS_KEY"),
  setup_test_file_with_env_var("AWS_CONFIG_FILE", "bad_config.ini"),
  setup_test_file_with_env_var("AWS_SHARED_CREDENTIALS_FILE",
                               "bad_credentials.ini"),
  meck:expect(httpc, request, 4, {error, timeout}).

setup_test_config_env_var() ->
  setup_test_file_with_env_var("AWS_CONFIG_FILE", "test_aws_config.ini").

setup_test_file_with_env_var(EnvVar, Filename) ->
  os:putenv(EnvVar,
            filename:join([filename:absname("."), "test",
                           Filename])).

setup_test_credentials_env_var() ->
  setup_test_file_with_env_var("AWS_SHARED_CREDENTIALS_FILE",
                               "test_aws_credentials.ini").

