defmodule SST.Secret.ConfigProviderTest do
  use ExUnit.Case
  doctest SST.Secret.ConfigProvider

  test "greets the world" do
    assert SST.Secret.ConfigProvider.hello() == :world
  end
end
