defmodule WebAuthnEx.AuthAssertionResponse do
  alias __MODULE__
  @enforce_keys [:credential_id, :auth_data_bytes, :signature]
  defstruct [:credential_id, :auth_data_bytes, :signature]
  def new(credential_id, auth_data_bytes, signature) do
    {:ok, %AuthAssertionResponse{credential_id: credential_id, auth_data_bytes: auth_data_bytes, signature: signature}}
  end

  def valid?(original_challenge, original_origin, allowed_credentials, rp_id, authenticator_data, %AuthAssertionResponse{} = auth_assertion_response) do
    WebAuthnEx.AuthenticatorResponse.valid?(original_challenge, original_origin, rp_id, authenticator_data) &&
      valid_credential?(allowed_credentials, auth_assertion_response) &&
      allowed_credentials
      |> credential_public_key(auth_assertion_response.client_id)
      |> valid_signature?(auth_assertion_response.client_id, auth_assertion_response)
  end

  def valid_credential?(allowed_credentials, %AuthAssertionResponse{} = auth_assertion_response) do
    allowed_credentials
    |> Enum.map(fn c -> c[:id] end)
    |> Enum.member?(auth_assertion_response.credential_id)
  end

  def valid_signature?(public_key_bytes, signature, %AuthAssertionResponse{} = auth_assertion_response) do
    # public_key = {{:ECPoint, public_key_bytes}, {:namedCurve, :prime256v1}}
    # :public_key.verify(auth_assertion_response.authenticator_data_bytes + client_data.hash, :sha256, signature, public_key)
    true
  end

  def credential_public_key(allowed_credentials, credential_id) do
    matched_credential = Enum.find(allowed_credentials, fn x -> x[:id] == credential_id end)
    matched_credential[:public_key]
  end
end
