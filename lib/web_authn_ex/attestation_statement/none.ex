defmodule WebAuthnEx.AttestationStatement.None do
  alias __MODULE__
  @enforce_keys [:statement]
  defstruct [:statement]
  def new(statement), do: {:ok, %None{statement: statement}}

  def valid?(_, _, _) do
    true
  end
end
