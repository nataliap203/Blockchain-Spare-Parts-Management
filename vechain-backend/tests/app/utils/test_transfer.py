import pytest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from src.app.utils.transfer import transfer_vtho

ENERGY_CONTRACT_ADDR = "0x0000000000000000000000000000456E65726779"


def test_transfer_vtho_success(mocker):
    """Test successful VTHO transfer. Checks if value is converted to Wei and correct contract is used."""
    mock_send_transaction = mocker.patch("src.app.utils.transfer.send_transaction", return_value="0xTransactionHash")

    sender_pk = "0x" + "a" * 64
    to_address = "0x" + "1" * 40
    amount_vtho = 50.0  # 50 VTHO

    result = transfer_vtho(sender_pk, to_address, amount_vtho)
    assert result == "0xTransactionHash"
    mock_send_transaction.assert_called_once()

    call_kwargs = mock_send_transaction.call_args.kwargs
    assert call_kwargs["contract_address"] == ENERGY_CONTRACT_ADDR
    assert call_kwargs["func_name"] == "transfer"
    assert call_kwargs["private_key"] == sender_pk

    contract_args = call_kwargs["args"]
    assert contract_args[0] == to_address
    expected_wei_amount = int(amount_vtho * 1e18)
    assert contract_args[1] == expected_wei_amount
    assert isinstance(contract_args[1], int)


def test_transfer_vtho_failure(mocker):
    """Test VTHO transfer failure handling."""
    mocker.patch("src.app.utils.transfer.send_transaction", side_effect=Exception("Transfer failed"))

    sender_pk = "0x" + "b" * 64
    to_address = "0x" + "2" * 40
    amount_vtho = 50.0  # 50 VTHO

    with pytest.raises(Exception) as exc_info:
        transfer_vtho(sender_pk, to_address, amount_vtho)

    assert "Failed to transfer VTHO" in str(exc_info.value)
    assert "Transfer failed" in str(exc_info.value)
