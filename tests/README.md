# AI_MAL Test Suite

This directory contains the test suite for the AI_MAL project. The tests cover all core functionality including scanning, AI analysis, Metasploit integration, and script generation.

## Test Structure

- `test_core.py`: Core functionality tests
- `conftest.py`: Test configuration and fixtures
- `requirements-test.txt`: Test dependencies
- `run_tests.sh`: Test execution script

## Running Tests

To run the tests:

1. Make sure you have Python 3.8 or higher installed
2. Run the test script:
   ```bash
   ./run_tests.sh
   ```

This will:
- Create a virtual environment if it doesn't exist
- Install test dependencies
- Run the test suite with coverage reporting
- Generate HTML coverage report

## Test Coverage

The test suite provides coverage reporting in two formats:
- Terminal output showing missing lines
- HTML report in the `htmlcov` directory

## Test Categories

### Core Functionality Tests

1. Scanner Tests
   - Initialization
   - Basic scanning
   - Aggressive scanning

2. AI Analysis Tests
   - Result analysis
   - Risk assessment
   - Vulnerability detection

3. Metasploit Integration Tests
   - Exploit finding
   - Exploit execution
   - Resource script generation

4. Script Generation Tests
   - Python script generation
   - Bash script generation
   - Ruby script generation
   - Script execution

### Integration Tests

- Full workflow testing
- Component interaction
- Error handling

## Adding New Tests

When adding new tests:

1. Add test functions to `test_core.py`
2. Use appropriate fixtures from `conftest.py`
3. Follow the existing test structure
4. Include docstrings explaining the test purpose
5. Add assertions to verify expected behavior

## Test Environment

The test environment is configured in `conftest.py` and includes:
- Test directories for resources, scripts, and logs
- Environment variables for configuration
- Event loop management for async tests
- Cleanup procedures

## Contributing

When contributing to the test suite:

1. Ensure all tests pass
2. Maintain or improve test coverage
3. Add tests for new features
4. Update documentation as needed
5. Follow the project's coding standards 