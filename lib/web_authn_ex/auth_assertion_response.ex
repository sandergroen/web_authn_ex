defmodule WebAuthnEx.AuthAssertionResponse do
  alias __MODULE__
  @enforce_keys [:credential_id, :auth_data_bytes, :signature]
  defstruct [:credential_id, :auth_data_bytes, :signature]

  def new(credential_id, auth_data_bytes, signature) do
    {:ok,
     %AuthAssertionResponse{
       credential_id: credential_id,
       auth_data_bytes: auth_data_bytes,
       signature: signature
     }}
  end

  def valid?(original_challenge, original_origin, allowed_credentials, rp_id, authenticator_data, client_data_json, %AuthAssertionResponse{} = auth_assertion_response) do
    WebAuthnEx.AuthenticatorResponse.valid?(original_challenge, original_origin, authenticator_data, rp_id, client_data_json) && valid_credential?(allowed_credentials, auth_assertion_response) &&
      allowed_credentials
      |> credential_public_key(auth_assertion_response.client_id)
      |> valid_signature?(auth_assertion_response.signature, client_data_json, auth_assertion_response.auth_data_bytes)
  end

  def valid_credential?(allowed_credentials, %AuthAssertionResponse{} = auth_assertion_response) do
    allowed_credentials
    |> Enum.map(fn c -> c[:id] end)
    |> Enum.member?(auth_assertion_response.credential_id)
  end

  def valid_signature?(public_key_bytes, signature, client_data_json, authenticator_data_bytes) do
    client_data_hash = :crypto.hash(:sha256, client_data_json)
    public_key = {{:ECPoint, public_key_bytes}, {:namedCurve, :prime256v1}}

    :public_key.verify(
      authenticator_data_bytes <> client_data_hash,
      :sha256,
      signature,
      public_key
    )
  end

  def credential_public_key(allowed_credentials, credential_id) do
    matched_credential = Enum.find(allowed_credentials, fn x -> x[:id] == credential_id end)
    matched_credential[:public_key]
  end
end
