defmodule WebAuthnEx.AttestationStatement do
  def from("fido-u2f", statement) do
    WebAuthnEx.AttestationStatement.FidoU2f.new(statement)
  end

  def from("packed", statement) do
    WebAuthnEx.AttestationStatement.FidoU2f.new(statement)
  end

  def from("android-safetynet", statement) do
    WebAuthnEx.AttestationStatement.FidoU2f.new(statement)
  end

  def from(format, _statement) do
    {:error, "Unsupported attestation format '#{format}'"}
  end
end
