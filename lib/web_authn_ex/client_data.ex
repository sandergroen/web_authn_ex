defmodule WebAuthnEx.ClientData do
  alias __MODULE__
  defstruct type: nil, challenge: nil, origin: nil, hash: nil

  def new(client_data_json) do
    client_data_json
    |> Jason.decode!()
    |> extract_data(client_data_json)
  end

  def extract_data(json, client_data_json) do
    {:ok, %ClientData{
        type: json["type"],
        challenge: json["challenge"],
        origin: json["origin"],
        hash: :crypto.hash(:sha256, client_data_json)
      }
    }
  end
end
