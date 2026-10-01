# Quick start: a first report in about 10 minutes (AWS)

Deploy the scanner into one AWS account and region, run it once, and open the
report it writes: where card numbers, Social Security numbers and other
sensitive data are, by store and location. No other tool is needed.
[A sample report](sample-report/report.html), made from the made-up
benchmark corpus, shows what you get.

**Before you start, plainly:**

- **It runs entirely in your account, read-only.** The stack creates a
  Lambda function, its role, a schedule and a results bucket. The role can
  read your data stores and write only to its own results bucket, and
  explicit `Deny` statements block writes to your data stores, so a mistake
  in the allow list cannot become a write
  ([Permissions](ARCHITECTURE.md#permissions-least-privilege)). Nothing
  leaves your account: no call home, no telemetry.
- **Every cost lands on your own AWS bill.** From [COST.md](COST.md), at
  us-east-1 list prices: one run is capped at about **$0.044** of Lambda
  compute (900 seconds at 3 GB). The quick start's first run reads at most
  256 MiB, which is a few minutes and cents at most, and often within the
  Lambda free tier; S3 requests are fractions of a cent. Left in place, the
  daily schedule is capped at about **$1.32 a month** of compute per account
  and region.
- **It is a beta.** AWS-only as a one-click deploy for now (Azure, Google
  Cloud, databases and SaaS deploy from [the README](../README.md#deploy-it)).
  Open source under the Apache License 2.0, provided as is, **without
  warranty**.
- **Feedback** goes to [GitHub issues](https://github.com/txp-labs/sensitive-data-scanner/issues).
  Please never paste a real value into an issue.

## 1. Deploy

Pick your region:

<!-- launch-stack:start -->
Version 0.5.0. Each button opens CloudFormation's quick-create page in that region with the release's own template.

| Region | | Launch |
|---|---|---|
| US East (N. Virginia) | `us-east-1` | [![Launch Stack in us-east-1](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-us-east-1.s3.us-east-1.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| US East (Ohio) | `us-east-2` | [![Launch Stack in us-east-2](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-2#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-us-east-2.s3.us-east-2.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| US West (Oregon) | `us-west-2` | [![Launch Stack in us-west-2](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-us-west-2.s3.us-west-2.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| Canada (Central) | `ca-central-1` | [![Launch Stack in ca-central-1](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=ca-central-1#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-ca-central-1.s3.ca-central-1.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| Europe (Ireland) | `eu-west-1` | [![Launch Stack in eu-west-1](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-eu-west-1.s3.eu-west-1.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| Europe (Frankfurt) | `eu-central-1` | [![Launch Stack in eu-central-1](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-eu-central-1.s3.eu-central-1.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
| Asia Pacific (Sydney) | `ap-southeast-2` | [![Launch Stack in ap-southeast-2](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacks/quickcreate?templateURL=https%3A%2F%2Ftxp-labs-sensitive-data-scanner-ap-southeast-2.s3.ap-southeast-2.amazonaws.com%2Freleases%2F0.5.0%2Fscanner.yaml&stackName=sensitive-data-scanner&param_Discover=all&param_MaxBytesPerRun=268435456) |
<!-- launch-stack:end -->

On the quick-create page, leave the defaults, tick **I acknowledge that AWS
CloudFormation might create IAM resources**, and choose **Create stack**. It
takes two or three minutes.

The defaults:

- **One account and region.** The stack is named `sensitive-data-scanner`,
  and so are its function and log group, so it is one stack per account and
  region. For a whole organization, see
  [Estate rollout](ARCHITECTURE.md#estate-rollout).
- **Discovery on** (`Discover=all`): every kind of store in the account and
  region is listed, and each one not read says why.
- **Opt-in reads off.** Reads that cost more or need more access (Redshift,
  EBS blocks, dead-letter queues, decrypted parameters and secrets, brokers,
  images) stay off, and the report names the setting for each
  ([limitations.md](limitations.md)).
- **A small first run** (`MaxBytesPerRun=268435456`, 256 MiB). What is left
  waits for the next runs.
- **Signed code.** The function runs the release's zip from txp-labs' bucket
  in your region, and a code signing configuration makes Lambda refuse any
  zip that txp-labs' signing profile for that region did not sign
  ([RELEASING.md](RELEASING.md#where-the-code-is)).

Or from the AWS CLI (version 2), with the version shown above:

```sh
REGION=us-east-1
VERSION=0.5.0   # the version in the table above
aws cloudformation create-stack --region "$REGION" --stack-name sensitive-data-scanner \
  --template-url "https://txp-labs-sensitive-data-scanner-$REGION.s3.$REGION.amazonaws.com/releases/$VERSION/scanner.yaml" \
  --capabilities CAPABILITY_IAM \
  --parameters ParameterKey=MaxBytesPerRun,ParameterValue=268435456
aws cloudformation wait stack-create-complete --region "$REGION" --stack-name sensitive-data-scanner
```

## 2. Run it once, now

The schedule runs it once a day. To run it now:

- **Console:** open **Lambda**, the function **sensitive-data-scanner**, the
  **Test** tab; keep the event `{}` and choose **Test**. The run takes a few
  minutes; the console waits for it.
- **CLI:** invoke it asynchronously (a synchronous CLI invoke can be retried
  by the CLI and start a second run; [Invoking a run](ARCHITECTURE.md#invoking-a-run)):

  ```sh
  aws lambda invoke --region "$REGION" --function-name sensitive-data-scanner \
    --invocation-type Event --cli-binary-format raw-in-base64-out --payload '{}' /dev/null
  aws logs tail /aws/lambda/sensitive-data-scanner --region "$REGION" --follow
  ```

  The run is done when the log shows `"event":"run.done"` (Ctrl-C to stop
  following).

## 3. Open the report

The run writes `findings/report.html` and `findings/findings.csv` next to the
findings document in the stack's results bucket. Make a link that works for
an hour, and open it in your browser:

```sh
BUCKET=$(aws cloudformation describe-stacks --region "$REGION" --stack-name sensitive-data-scanner \
  --query "Stacks[0].Outputs[?OutputKey=='ResultsBucket'].OutputValue" --output text)
aws s3 presign "s3://$BUCKET/findings/report.html" --region "$REGION" --expires-in 3600
aws s3 cp "s3://$BUCKET/findings/findings.csv" . --region "$REGION"
```

The report holds no value, but it does name your buckets, keys, tables and
log groups: treat the link, which anyone holding it can open until it
expires, like the report itself.

It shows what was scanned and what was not (each gap with the setting that
would read it), the findings by data type, by store and by location (each
with a link into your own console), the storage classes and what reading the
cold ones would cost, and the scanner version and run. Each run replaces it
with the latest.

To read more than the first 256 MiB a run, update the stack with
`MaxBytesPerRun` empty (the scanner's default, 2 GiB), or invoke it again:
each run goes on where the last stopped.

## 4. Remove it

```sh
aws cloudformation delete-stack --region "$REGION" --stack-name sensitive-data-scanner
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name sensitive-data-scanner
aws s3 rm "s3://$BUCKET" --recursive --region "$REGION"
aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION"
```

The results bucket is kept when the stack is deleted, so findings are never
lost by accident; the last two commands delete it. In the console: delete the
stack in **CloudFormation**, then **Empty** and **Delete** the bucket in
**S3**.
