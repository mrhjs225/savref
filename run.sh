#!/bin/bash

# LLM-based Vulnerability Fixing Technology Execution Script

# Set Python path to include the current directory
export PYTHONPATH="$PYTHONPATH:$(pwd)"

# Load environment variables file (if exists)
if [ -f .env ]; then
  echo "Loading environment variables from .env file"
  export $(cat .env | grep -v '#' | xargs)
fi

# Parse command line arguments
PARAM_BUG_ID=""
PARAM_MODEL_TYPE="openai"
PARAM_MODEL_SIZE="large"
PARAM_USE_GRAPH=false
PARAM_EVAL=true
PARAM_VERBOSE=false

# Parse arguments
while [ $# -gt 0 ]; do
  key="$1"
  
  case $key in
    --bug_id)
      PARAM_BUG_ID="$2"
      shift
      shift
      ;;
    --model_type)
      PARAM_MODEL_TYPE="$2"
      shift
      shift
      ;;
    --model_size)
      PARAM_MODEL_SIZE="$2"
      shift
      shift
      ;;
    --use_graph)
      PARAM_USE_GRAPH=true
      shift
      ;;
    --no_eval)
      PARAM_EVAL=false
      shift
      ;;
    --verbose)
      PARAM_VERBOSE=true
      shift
      ;;
    --help)
      echo "Usage: run.sh [options]"
      echo "Options:"
      echo "  --bug_id ID         Process specific bug ID (if not specified, process all bugs)"
      echo "  --model_type TYPE   Model type (openai, anthropic, local_slm) (default: openai)"
      echo "  --model_size SIZE   Model size (1b, 10b, large) (default: large)"
      echo "  --use_graph         Use graph information"
      echo "  --no_eval           Skip evaluation step"
      echo "  --verbose           Output detailed logs"
      echo "  --help              Display this help message"
      exit 0
      ;;
    *)
      echo "Unknown argument: $key"
      echo "Use --help to see usage."
      exit 1
      ;;
  esac
done

# Configure command
CMD="python -m run.main"

if [ -n "$PARAM_BUG_ID" ]; then
  CMD="$CMD --bug_id $PARAM_BUG_ID"
fi

CMD="$CMD --model_type $PARAM_MODEL_TYPE --model_size $PARAM_MODEL_SIZE"

if [ "$PARAM_USE_GRAPH" = true ]; then
  CMD="$CMD --use_graph"
fi

if [ "$PARAM_EVAL" = false ]; then
  CMD="$CMD --no_evaluate"
fi

# Debug output
echo "Current directory: $(pwd)"
echo "Python path: $PYTHONPATH"
echo "Executing command: $CMD"

# Execute
if [ "$PARAM_VERBOSE" = true ]; then
  $CMD
else
  $CMD 2>&1 | grep -v "DEBUG"
fi