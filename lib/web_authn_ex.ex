defmodule WebAuthnEx do
  @moduledoc """
  Documentation for WebAuthnEx.
  """
  # credo:disable-for-next-line
  @cred_param_ES256 %{type: "public-key", alg: -7}
  @user_id "1"
  @user_name "web-user"

  def credential_creation_options(rp_name, rp_id) do
    %{
      challenge: challenge(),
      # credo:disable-for-next-line
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
