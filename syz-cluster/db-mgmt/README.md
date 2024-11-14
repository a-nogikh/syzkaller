How to run DB migrations locally:

```
cd $SYZKALLER/syz-cluster
make build-db-mgmt-dev restart-spanner
./db-mgmt/run-local.sh migrate /migrations
```
