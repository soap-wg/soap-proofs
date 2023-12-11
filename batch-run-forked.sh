for arg in "$@"
do
  source ./batch-run.sh "$arg" "--prove=$arg" &
done
