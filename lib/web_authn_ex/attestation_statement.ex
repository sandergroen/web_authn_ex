defmodule WebAuthnEx.AttestationStatement do
  @moduledoc """
  Verifies attestation statement of various types.
  """
  alias WebAuthnEx.AttestationStatement.{FidoU2f, None}

  def from("fido-u2f", statement) do
    FidoU2f.new(statement)
  end

  def from("none", statement) do
    None.new(statement)
  end

  # def from("packed", statement) do
  #   WebAuthnEx.AttestationStatement.FidoU2f.new(statement)
  # end

  # def from("android-safetynet", statement) do
  #   WebAuthnEx.AttestationStatement.FidoU2f.new(statement)
  # end

  def from(format, _statement) do
    {:error, "Unsupported attestation format '#{format}'"}
  end

  def valid?("none", authenticator_data, client_data_hash, attestation_statement) do
    None.valid?(
      authenticator_data,
      client_data_hash,
      attestation_statement
    )
  end

  def valid?("fido-u2f", authenticator_data, client_data_hash, attestation_statement) do
    FidoU2f.valid?(
      authenticator_data,
      client_data_hash,
      attestation_statement
    )
  end
end
