"""The Google Cloud scanner of the sensitive data scanner: findings only, never values.

A Cloud Run job with a dedicated service account runs it in the customer's own
organization. It discovers the data stores of every project under an
organization or folder (Cloud Asset Inventory), reads them read-only with the
service account's viewer and reader permissions, and pushes findings only.
Every store it cannot read is in the run summary with a reason. Detection, the
findings contract, budgets, sampling and the readers are the core's
(`sensitive_data_core`); Google's libraries are imported here and nowhere else.
"""

__version__ = "0.6.0"
