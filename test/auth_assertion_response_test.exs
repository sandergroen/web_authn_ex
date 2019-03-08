defmodule AuthAssertionResponseTest do
  use ExUnit.Case
  doctest WebAuthnEx.AuthAssertionResponse
  @original_challenge FakeAuthenticator.fake_challenge()
  @original_origin FakeAuthenticator.fake_origin()
  @authenticator FakeAuthenticator.get(%{
                   challenge: @original_challenge,
                   context: %{origin: @original_origin}
                 })
  @credential_key @authenticator.credential_key
  @credential_id @authenticator.credential_id
  @allowed_credentials [
    %{id: @credential_id, public_key: FakeAuthenticator.public_key(@credential_key)}
  ]
  @authenticator_data @authenticator.authenticator_data

  test "is valid if everything's in place" do
    assert WebAuthnEx.AuthAssertionResponse.new(
             @credential_id,
             @authenticator_data,
             @authenticator.signature,
             @original_challenge,
             @original_origin,
             @allowed_credentials,
             @authenticator.rp_id,
             @authenticator.client_data_json
           )
  end

  test "is valid with more than one allowed credential" do
    {public_key, _} = :crypto.generate_key(:ecdh, :prime256v1)

    allowed_credentials = [
      %{
        id: 16 |> :crypto.strong_rand_bytes(),
        public_key: public_key
      }
      | @allowed_credentials
    ]

    assert WebAuthnEx.AuthAssertionResponse.new(
             @credential_id,
             @authenticator_data,
             @authenticator.signature,
             @original_challenge,
             @original_origin,
             allowed_credentials,
             @authenticator.rp_id,
             @authenticator.client_data_json
           )
  end

  test "is invalid if signature was signed with a different key" do
    public_key =
      FakeAuthenticator.get().credential_key
      |> FakeAuthenticator.public_key()

    allowed_credentials = [
      %{
        id: @credential_id,
        public_key: public_key
      }
    ]

    assert {:error, "Validation of signature failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               @authenticator_data,
               @authenticator.signature,
               @original_challenge,
               @original_origin,
               allowed_credentials,
               @authenticator.rp_id,
               @authenticator.client_data_json
             )
  end

  test "is invalid if credential id is not among the allowed ones" do
    allowed_credentials = [
      %{
        id: 16 |> :crypto.strong_rand_bytes(),
        public_key: FakeAuthenticator.public_key(@credential_key)
      }
    ]

    assert {:error, "Validation of credential failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               @authenticator_data,
               @authenticator.signature,
               @original_challenge,
               @original_origin,
               allowed_credentials,
               @authenticator.rp_id,
               @authenticator.client_data_json
             )
  end

  test "type validation is invalid if type is create instead of get" do
    authenticator =
      FakeAuthenticator.get_wrong_type(%{
        challenge: @original_challenge,
        context: %{origin: @original_origin}
      })

    assert {:error, "Validation of authenticator failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               authenticator.authenticator_data,
               authenticator.signature,
               @original_challenge,
               @original_origin,
               @allowed_credentials,
               authenticator.rp_id,
               authenticator.client_data_json
             )
  end

  test "user present validation is invalid if user flags are off" do
    authenticator =
      FakeAuthenticator.get(%{
        challenge: @original_challenge,
        context: %{
          origin: @original_origin,
          user_present: false,
          user_verified: false
        }
      })

    assert {:error, "Validation of authenticator failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               authenticator.authenticator_data,
               authenticator.signature,
               @original_challenge,
               @original_origin,
               @allowed_credentials,
               authenticator.rp_id,
               authenticator.client_data_json
             )
  end

  test "challenge validation is invalid if challenge doesn't match" do
    assert {:error, "Validation of authenticator failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               @authenticator.authenticator_data,
               @authenticator.signature,
               FakeAuthenticator.fake_challenge(),
               @original_origin,
               @allowed_credentials,
               @authenticator.rp_id,
               @authenticator.client_data_json
             )
  end

  test "origin validation is invalid if origin doesn't match" do
    assert {:error, "Validation of authenticator failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               @authenticator.authenticator_data,
               @authenticator.signature,
               @original_challenge,
               "http://different-origin",
               @allowed_credentials,
               @authenticator.rp_id,
               @authenticator.client_data_json
             )
  end

  test "rp_id validation is invalid if rp_id_hash doesn't match" do
    authenticator =
      FakeAuthenticator.get(%{
        challenge: @original_challenge,
        rp_id: "different-rp_id",
        context: %{
          origin: @original_origin
        }
      })

    assert {:error, "Validation of signature failed!"} =
             WebAuthnEx.AuthAssertionResponse.new(
               @credential_id,
               authenticator.authenticator_data,
               authenticator.signature,
               @original_challenge,
               @original_origin,
               @allowed_credentials,
               authenticator.rp_id,
               authenticator.client_data_json
             )
  end

  test "when rp_id is explicitly given is valid if correct rp_id is given" do
    authenticator =
      FakeAuthenticator.get(%{
        challenge: @original_challenge,
        rp_id: "different-rp_id",
        context: %{
          origin: @original_origin
        }
      })

    allowed_credentials = [
      %{
        id: authenticator.credential_id,
        public_key: FakeAuthenticator.public_key(authenticator.credential_key)
      }
    ]

    assert WebAuthnEx.AuthAssertionResponse.new(
             authenticator.credential_id,
             authenticator.authenticator_data,
             authenticator.signature,
             @original_challenge,
             @original_origin,
             allowed_credentials,
             "different-rp_id",
             authenticator.client_data_json
           )
  end
end
