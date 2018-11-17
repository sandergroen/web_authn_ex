defmodule WebAuthnEx.AttestationStatement.FidoU2f do
  alias __MODULE__
  @enforce_keys [:statement]
  defstruct [:statement]

  def new(statement), do: {:ok, %FidoU2f{statement: statement}}

  @behaviour WebAuthnEx.AttestationStatement.AttestationStatementBehaviour

  def valid?(authenticator_data, client_data_hash) do
    true
    # valid_format? &&
    #       valid_certificate_public_key? &&
    #       valid_signature?(authenticator_data, client_data_hash)
  end
end
