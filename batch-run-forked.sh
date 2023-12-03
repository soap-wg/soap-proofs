for arg in "$@"
do
  ./batch-run.sh "$arg" "--prove=$arg" &
done
