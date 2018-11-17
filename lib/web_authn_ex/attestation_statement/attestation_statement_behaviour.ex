defmodule WebAuthnEx.AttestationStatement.AttestationStatementBehaviour do
  @callback valid?(authenticator_data :: string, client_data_hash :: string) :: boolean
end
