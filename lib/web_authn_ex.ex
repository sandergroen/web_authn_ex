defmodule WebAuthnEx do
  @moduledoc """
  Documentation for WebAuthnEx.
  """

  @cred_param_ES256 %{type: "public-key", alg: -7}
  @user_id "1"
  @user_name "web-user"
  @types %{create: "webauthn.create", get: "webauthn.get"}

  def credential_creation_options(rp_name, rp_id) do
    %{
      challenge: challenge(),
      pubKeyCredParams: [@cred_param_ES256],
      rp: %{name: rp_name, id: rp_id},
      user: %{name: @user_name, displayName: @user_name, id: @user_id}
    }
  end

  def credential_request_options do
    %{
      challenge: challenge(),
      allowCredentials: []
    }
  end

  defp challenge do
    :crypto.strong_rand_bytes(32)
  end
end