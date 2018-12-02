defmodule CredentialTest do
  use ExUnit.Case
  doctest WebAuthnEx.Credential
  alias WebAuthnEx.Credential

  def raw_attested_credential_data(options \\ %{}) do
    options =
      options
      |> Map.put(:aaguid, 16 |> :crypto.strong_rand_bytes())
      |> Map.put(:id, 16 |> :crypto.strong_rand_bytes())
      |> Map.put(:public_key, options.public_key || FakeAuthenticator.fake_cose_credential_key())

    options.aaguid <>
      <<byte_size(options.id)::big-integer-size(16)>> <> options.id <> options.public_key
  end

  test "#valid? returns false if public key is missing" do
    raw_data = raw_attested_credential_data(%{public_key: ""})
    refute Credential.valid?(raw_data)
    refute Credential.new(raw_data).public_key
  end
end
