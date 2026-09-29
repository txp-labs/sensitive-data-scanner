import sensitive_data_scanner


def test_package_imports() -> None:
    assert sensitive_data_scanner.__version__
