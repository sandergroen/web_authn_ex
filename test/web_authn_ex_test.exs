defmodule WebAuthnExTest do
  use ExUnit.Case

  doctest WebAuthnEx
  @credential_options WebAuthnEx.credential_creation_options("web-server", "example.com")
  @credential_request_options WebAuthnEx.credential_request_options

  test "credential_options has a 32 byte length challenge" do
    assert byte_size(@credential_options.challenge) == 32
  end

  test "credential_options has public key params" do
    assert Enum.at(@credential_options.pubKeyCredParams, 0)[:type] == "public-key"
    assert Enum.at(@credential_options.pubKeyCredParams, 0)[:alg] == -7
  end

  test "credential_options has relying party info" do
    assert @credential_options[:rp][:name] == "web-server"
  end

  test "credential_options has user info" do
    user_info = @credential_options[:user]
    assert user_info[:name] == "web-user"
    assert user_info[:displayName] == "web-user"
    assert user_info[:id] == "1"
  end

  test "request_options has a 32 byte length challenge" do
    assert byte_size(@credential_request_options[:challenge]) == 32
  end

  test "request_options has allowCredentials param with an empty array" do
    assert @credential_request_options.allowCredentials == []
  end
end
