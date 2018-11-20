defmodule WebauthnEx.EC2Key do
  @alg_label 3
  @crv_label -1
  @x_label -2
  @y_label -3
  @kty_ec2 2
  @kty_label 1


  alias __MODULE__
  defstruct [:algorithm, :curve, :x_coordinate, :y_coordinate]
  def new(algorithm, curve, x_coordinate, y_coordinate) do
    %EC2Key{algorithm: algorithm, curve: curve, x_coordinate: x_coordinate, y_coordinate: y_coordinate}
  end

  def from_cbor(cbor) do
    from_map(:cbor.decode(cbor))
  end

  def from_map(map) do
    %{@alg_label => algoritm, @crv_label => curve, @x_label => x_coordinate, @y_label => y_coordinate} = map
    new(algoritm, curve, x_coordinate, y_coordinate)
    # case enforce_type(map) do
    #   :ok -> new(algoritm, curve, x_coordinate, y_coordinate)
    #   :error -> :error
    # end
  end

  def enforce_type(map) do
    %{@kty_label => label} = map
    case label do
      @kty_ec2 -> :ok
      _ -> :error
    end
  end
end
