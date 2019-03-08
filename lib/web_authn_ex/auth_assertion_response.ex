defmodule WebAuthnEx.AuthAssertionResponse do
  @moduledoc """
  Validates assertion
  """
  alias WebAuthnEx.AuthenticatorResponse
  alias __MODULE__
  @enforce_keys [:credential_id, :auth_data_bytes, :signature]
  defstruct [
    :credential_id,
    :auth_data_bytes,
    :signature,
    :allowed_credentials,
    :valid_authenticator,
    :valid_assertion_statement,
    :valid_credential,
    :valid_signature
  ]

  def new(
        credential_id,
        auth_data_bytes,
        signature,
        challenge,
        original_origin,
        allowed_credentials,
        rp_id,
        client_data_json
      ) do
    %AuthAssertionResponse{
      credential_id: credential_id,
      auth_data_bytes: auth_data_bytes,
      signature: signature,
      allowed_credentials: allowed_credentials,
      valid_authenticator: nil,
      valid_assertion_statement: nil,
      valid_credential: nil,
      valid_signature: nil
    }
    |> valid?(challenge, original_origin, rp_id, client_data_json)
    |> result()
  end

  def result(
        %AuthAssertionResponse{
          valid_authenticator: valid_authenticator,
          valid_assertion_statement: valid_assertion_statement,
          valid_credential: valid_credential,
          valid_signature: valid_signature
        } = auth_assertion_response
      ) do
    cond do
      valid_authenticator == false ->
        {:error, "Validation of authenticator failed!"}

      valid_assertion_statement == false ->
        {:error, "Validation of assertion statement failed!"}

      valid_credential == false ->
        {:error, "Validation of credential failed!"}

      valid_signature == false ->
        {:error, "Validation of signature failed!"}

      true ->
        {:ok, auth_assertion_response}
    end
  end

  def valid?(
        %AuthAssertionResponse{} = auth_assertion_response,
        original_challenge,
        original_origin,
        rp_id,
        client_data_json
      ) do
    auth_assertion_response
    |> valid_authenticator_response?(
      original_challenge,
      original_origin,
      auth_assertion_response.auth_data_bytes,
      rp_id,
      client_data_json
    )
    |> valid_credential?()
    |> valid_signature?(client_data_json)
  end

  def valid_authenticator_response?(
        auth_assertion_response,
        original_challenge,
        original_origin,
        auth_data_bytes,
        rp_id,
        client_data_json
      ) do
    case AuthenticatorResponse.valid?(
           original_challenge,
           original_origin,
           auth_data_bytes,
           rp_id,
           client_data_json
         ) do
      true ->
        %AuthAssertionResponse{auth_assertion_response | valid_authenticator: true}

      false ->
        %AuthAssertionResponse{auth_assertion_response | valid_authenticator: false}
    end
  end

  def valid_credential?(%AuthAssertionResponse{} = auth_assertion_response) do
    credential_valid =
      auth_assertion_response.allowed_credentials
      |> Enum.map(fn c -> c[:id] end)
      |> Enum.member?(auth_assertion_response.credential_id)

    case credential_valid do
      true ->
        %AuthAssertionResponse{auth_assertion_response | valid_credential: true}

      false ->
        %AuthAssertionResponse{auth_assertion_response | valid_credential: false}
    end
  end

  def valid_signature?(
        auth_assertion_response,
        client_data_json
      ) do
    public_key_bytes = auth_assertion_response |> credential_public_key()
    client_data_hash = :crypto.hash(:sha256, client_data_json)
    public_key = {{:ECPoint, public_key_bytes}, {:namedCurve, :prime256v1}}

    signature_valid =
      :public_key.verify(
        auth_assertion_response.auth_data_bytes <> client_data_hash,
        :sha256,
        auth_assertion_response.signature,
        public_key
      )

    case signature_valid do
      true ->
        %AuthAssertionResponse{auth_assertion_response | valid_signature: true}

      false ->
        %AuthAssertionResponse{auth_assertion_response | valid_signature: false}
    end
  end

  def credential_public_key(auth_assertion_response) do
    if auth_assertion_response.valid_credential do
      matched_credential =
        Enum.find(auth_assertion_response.allowed_credentials, fn x ->
          x[:id] == auth_assertion_response.credential_id
        end)

      matched_credential[:public_key]
    end
  end
end
