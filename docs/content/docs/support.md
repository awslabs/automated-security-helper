# Support Matrix

ASH itself should support running in any environment that can support running `linux/amd64` container images.

## Local Execution

The table below provides a matrix of **tested** runtime environments for ASH.

|          OCI Container Tool           |          Host          |    Full Support    | Partial Support | No Support | Untested |
|:-------------------------------------:|:----------------------:|:------------------:|:---------------:|:----------:|:--------:|
|                 Finch                 |     macOS w/ Intel     | :white_check_mark: |                 |            |          |
|                 Finch                 | macOS w/ Apple Silicon | :white_check_mark: |                 |            |          |
|            Docker Desktop             |     macOS w/ Intel     | :white_check_mark: |                 |            |          |
|            Docker Desktop             | macOS w/ Apple Silicon | :white_check_mark: |                 |            |          |
|    Rancher Desktop w/ docker+moby     |     macOS w/ Intel     | :white_check_mark: |                 |            |          |
|    Rancher Desktop w/ docker+moby     | macOS w/ Apple Silicon | :white_check_mark: |                 |            |          |
| Rancher Desktop w/ nerdctl+containerd |     macOS w/ Intel     | :white_check_mark: |                 |            |          |
| Rancher Desktop w/ nerdctl+containerd | macOS w/ Apple Silicon | :white_check_mark: |                 |            |          |

## Continuous Integration

The table below provides a matrix of **tested** CI execution environment for ASH.

For more information, please see [Running ASH in CI](../tutorials/running-ash-in-ci.md)

|              CI Platform               | Execution Method |    Full Support    | Partial Support | No Support | Untested |
|:--------------------------------------:|:----------------:|:------------------:|:---------------:|:----------:|:--------:|
|               GitLab CI                |  Container Job   | :white_check_mark: |                 |            |          |
|               GitLab CI                |   `docker run`   | :white_check_mark: |                 |            |          |
| GitHub Actions (hosted  Ubuntu agents) |  Container Job   | :white_check_mark: |                 |            |          |
| GitHub Actions (hosted  Ubuntu agents) |   `docker run`   | :white_check_mark: |                 |            |          |
| Azure Pipelines (hosted Ubuntu agents) |  Container Job   | :white_check_mark: |                 |            |          |
| Azure Pipelines (hosted Ubuntu agents) |   `docker run`   | :white_check_mark: |                 |            |          |
|                Jenkins                 |   `docker run`   | :white_check_mark: |                 |            |          |
