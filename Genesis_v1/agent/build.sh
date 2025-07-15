#!/bin/bash

# GENESIS Agent Build Script
# This script builds the GENESIS agent with proper error handling and options

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
BUILD_TYPE="Release"
BUILD_TESTS="ON"
CLEAN_BUILD=false
VERBOSE=false
INSTALL=false
RUN_TESTS=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[GENESIS]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "GENESIS Agent Build Script"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -d, --debug         Build in Debug mode (default: Release)"
    echo "  -c, --clean         Clean build directory before building"
    echo "  -t, --tests         Enable building tests (default: ON)"
    echo "  --no-tests          Disable building tests"
    echo "  -v, --verbose       Verbose build output"
    echo "  -i, --install       Install after building"
    echo "  -r, --run-tests     Run tests after building"
    echo "  --parallel N        Use N parallel jobs (default: auto-detect)"
    echo ""
    echo "Examples:"
    echo "  $0                  # Basic release build"
    echo "  $0 -d -t -r         # Debug build with tests that run after build"
    echo "  $0 -c --parallel 4  # Clean build with 4 parallel jobs"
}

# Parse command line arguments
PARALLEL_JOBS=$(nproc 2>/dev/null || echo 4)

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -c|--clean)
            CLEAN_BUILD=true
            shift
            ;;
        -t|--tests)
            BUILD_TESTS="ON"
            shift
            ;;
        --no-tests)
            BUILD_TESTS="OFF"
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -i|--install)
            INSTALL=true
            shift
            ;;
        -r|--run-tests)
            RUN_TESTS=true
            shift
            ;;
        --parallel)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_ROOT/build"

print_status "Starting GENESIS Agent build..."
print_status "Project root: $PROJECT_ROOT"
print_status "Build type: $BUILD_TYPE"
print_status "Build tests: $BUILD_TESTS"
print_status "Parallel jobs: $PARALLEL_JOBS"

# Check for required tools
check_requirements() {
    print_status "Checking build requirements..."
    
    local missing_tools=()
    
    if ! command -v cmake &> /dev/null; then
        missing_tools+=("cmake")
    fi
    
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        missing_tools+=("g++ or clang++")
    fi
    
    if ! command -v make &> /dev/null && ! command -v ninja &> /dev/null; then
        missing_tools+=("make or ninja")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        print_status "Install missing tools and try again"
        exit 1
    fi
    
    # Check CMake version
    CMAKE_VERSION=$(cmake --version | head -n1 | cut -d' ' -f3)
    print_status "Found CMake version: $CMAKE_VERSION"
    
    # Check compiler
    if command -v g++ &> /dev/null; then
        GCC_VERSION=$(g++ --version | head -n1)
        print_status "Found compiler: $GCC_VERSION"
    elif command -v clang++ &> /dev/null; then
        CLANG_VERSION=$(clang++ --version | head -n1)
        print_status "Found compiler: $CLANG_VERSION"
    fi
    
    print_success "All requirements satisfied"
}

# Clean build directory if requested
clean_build() {
    if [[ "$CLEAN_BUILD" == true ]]; then
        print_status "Cleaning build directory..."
        if [[ -d "$BUILD_DIR" ]]; then
            rm -rf "$BUILD_DIR"
            print_success "Build directory cleaned"
        else
            print_status "Build directory doesn't exist, nothing to clean"
        fi
    fi
}

# Configure the build
configure_build() {
    print_status "Configuring build..."
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    local cmake_args=(
        "-DCMAKE_BUILD_TYPE=$BUILD_TYPE"
        "-DBUILD_TESTS=$BUILD_TESTS"
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
    )
    
    # Add verbose flag if requested
    if [[ "$VERBOSE" == true ]]; then
        cmake_args+=("-DCMAKE_VERBOSE_MAKEFILE=ON")
    fi
    
    # Detect and use Ninja if available
    if command -v ninja &> /dev/null; then
        cmake_args+=("-GNinja")
        print_status "Using Ninja build system"
    else
        print_status "Using Make build system"
    fi
    
    print_status "CMake command: cmake ${cmake_args[*]} $PROJECT_ROOT"
    
    if ! cmake "${cmake_args[@]}" "$PROJECT_ROOT"; then
        print_error "CMake configuration failed"
        exit 1
    fi
    
    print_success "Build configured successfully"
}

# Build the project
build_project() {
    print_status "Building GENESIS agent..."
    
    cd "$BUILD_DIR"
    
    local build_args=()
    
    if command -v ninja &> /dev/null && [[ -f "build.ninja" ]]; then
        build_args+=("-j$PARALLEL_JOBS")
        if [[ "$VERBOSE" == true ]]; then
            build_args+=("-v")
        fi
        print_status "Build command: ninja ${build_args[*]}"
        if ! ninja "${build_args[@]}"; then
            print_error "Build failed"
            exit 1
        fi
    else
        build_args+=("-j$PARALLEL_JOBS")
        if [[ "$VERBOSE" == true ]]; then
            build_args+=("VERBOSE=1")
        fi
        print_status "Build command: make ${build_args[*]}"
        if ! make "${build_args[@]}"; then
            print_error "Build failed"
            exit 1
        fi
    fi
    
    print_success "Build completed successfully"
}

# Install the project
install_project() {
    if [[ "$INSTALL" == true ]]; then
        print_status "Installing GENESIS agent..."
        
        cd "$BUILD_DIR"
        
        if command -v ninja &> /dev/null && [[ -f "build.ninja" ]]; then
            if ! ninja install; then
                print_error "Installation failed"
                exit 1
            fi
        else
            if ! make install; then
                print_error "Installation failed"
                exit 1
            fi
        fi
        
        print_success "Installation completed"
    fi
}

# Run tests
run_tests() {
    if [[ "$RUN_TESTS" == true && "$BUILD_TESTS" == "ON" ]]; then
        print_status "Running tests..."
        
        cd "$BUILD_DIR"
        
        if [[ -f "tests/genesis_tests" ]]; then
            print_status "Running unit tests..."
            if ! ./tests/genesis_tests; then
                print_error "Unit tests failed"
                exit 1
            fi
            print_success "Unit tests passed"
        else
            print_warning "Test executable not found, skipping tests"
        fi
        
        # Run individual test suites if available
        if [[ -f "tests/test_security" ]]; then
            print_status "Running security tests..."
            if ! ./tests/test_security; then
                print_error "Security tests failed"
                exit 1
            fi
            print_success "Security tests passed"
        fi
        
        if [[ -f "tests/test_integration" ]]; then
            print_status "Running integration tests..."
            if ! ./tests/test_integration; then
                print_error "Integration tests failed"
                exit 1
            fi
            print_success "Integration tests passed"
        fi
    elif [[ "$RUN_TESTS" == true && "$BUILD_TESTS" == "OFF" ]]; then
        print_warning "Tests requested but BUILD_TESTS is OFF"
    fi
}

# Show build results
show_results() {
    print_status "Build Summary:"
    echo "  Build Type: $BUILD_TYPE"
    echo "  Tests Built: $BUILD_TESTS"
    echo "  Build Directory: $BUILD_DIR"
    
    if [[ -f "$BUILD_DIR/genesis_agent" ]]; then
        local binary_size=$(du -h "$BUILD_DIR/genesis_agent" | cut -f1)
        echo "  Binary Size: $binary_size"
        print_success "GENESIS agent binary created: $BUILD_DIR/genesis_agent"
    else
        print_error "GENESIS agent binary not found!"
        exit 1
    fi
    
    if [[ "$BUILD_TESTS" == "ON" ]]; then
        local test_count=$(find "$BUILD_DIR/tests" -type f -executable 2>/dev/null | wc -l)
        echo "  Test Executables: $test_count"
    fi
    
    echo ""
    print_success "Build completed successfully!"
    
    if [[ "$INSTALL" == false ]]; then
        echo ""
        print_status "To run GENESIS agent:"
        echo "  cd $BUILD_DIR && ./genesis_agent --help"
    fi
    
    if [[ "$BUILD_TESTS" == "ON" && "$RUN_TESTS" == false ]]; then
        echo ""
        print_status "To run tests manually:"
        echo "  cd $BUILD_DIR && ./tests/genesis_tests"
    fi
}

# Main build process
main() {
    check_requirements
    clean_build
    configure_build
    build_project
    install_project
    run_tests
    show_results
}

# Trap errors and show helpful message
trap 'print_error "Build failed at line $LINENO"' ERR

# Run main function
main "$@"