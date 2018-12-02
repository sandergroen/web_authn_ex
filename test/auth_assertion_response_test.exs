defmodule AuthAssertionResponseTest do
  use ExUnit.Case
  doctest WebAuthnEx.AuthAssertionResponse

  test "valid_signature attestation_response" do
    authenticator = FakeAuthenticator.get()

    {:ok, auth_response} =
      WebAuthnEx.AuthAssertionResponse.new(
        authenticator.credential_id,
        authenticator.authenticator_data,
        authenticator.signature
      )

    assert WebAuthnEx.AuthAssertionResponse.valid?(
             authenticator.challenge,
             authenticator.origin,
             allowed_credentials(authenticator),
             authenticator.rp_id,
             authenticator.client_data_json,
             auth_response
           )
  end

  defp allowed_credentials(%FakeAuthenticator{} = authenticator) do
    {public_key, _} = authenticator.credential_key

    [
      %{
        id: authenticator.credential_id,
        public_key: public_key
      }
    ]
  end
end
