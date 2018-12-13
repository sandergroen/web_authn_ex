defmodule WebAuthnEx.ClientData do
  @moduledoc """
    WebAuthnEx.ClientData decodes client_data_json to ClientData struct
  """

  alias __MODULE__
  defstruct type: nil, challenge: nil, origin: nil, hash: nil

  def new(client_data_json) do
    client_data_json
    |> Jason.decode!()
    |> extract_data(client_data_json)
  end

  def extract_data(json, client_data_json) do
    cond do
      Map.has_key?(json, "type") == false ->
        {:error, "Type is missing"}

      Map.has_key?(json, "challenge") == false ->
        {:error, "Challenge is missing"}

      Map.has_key?(json, "origin") == false ->
        {:error, "Origin is missing"}

      true ->
        {:ok,
         %ClientData{
           type: json["type"],
           challenge: json["challenge"],
           origin: json["origin"],
           hash: :crypto.hash(:sha256, client_data_json)
         }}
    end
  end
end
