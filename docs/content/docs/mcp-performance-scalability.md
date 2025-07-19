# MCP Server Performance and Scalability

This guide covers performance optimization and scalability considerations for the ASH MCP server.

## Overview

The ASH MCP server in v3 includes comprehensive resource management designed to handle concurrent operations efficiently while preventing memory leaks and resource exhaustion. This guide helps you optimize performance for your specific use case.

## Performance Features

### Resource Management

- **Concurrent Operation Control**: Configurable limits on simultaneous scans and tasks
- **Memory Leak Prevention**: Automatic tracking and cleanup of async tasks and event handlers
- **Shared Resource Pool**: Efficient thread pool management across operations
- **Graceful Degradation**: Automatic protection against resource exhaustion

### Monitoring and Observability

- **Real-time Monitoring**: Built-in health checks and resource usage tracking
- **Performance Metrics**: Task counts, memory usage, and operation timings
- **Alerting Thresholds**: Configurable warnings for resource usage
- **Detailed Logging**: Optional verbose logging for performance analysis

## Configuration for Performance

### Basic Performance Configuration

```yaml
# .ash/ash.yaml - Optimized for performance
mcp-resource-management:
  # Concurrent operations - adjust based on system resources
  max_concurrent_scans: 5              # Higher for powerful systems
  max_concurrent_tasks: 30             # Increase for complex scans
  thread_pool_max_workers: 8           # Match CPU core count

  # Timeouts - balance speed vs completeness
  scan_timeout_seconds: 2400           # 40 minutes for large projects
  operation_timeout_seconds: 300       # 5 minutes for operations

  # Resource monitoring
  enable_health_checks: true
  health_check_interval_seconds: 30    # Frequent monitoring
```

### High-Performance Configuration

For powerful systems with ample resources:

```yaml
# .ash/ash.yaml - High-performance setup
mcp-resource-management:
  # Maximize concurrent operations
  max_concurrent_scans: 8
  max_concurrent_tasks: 50
  thread_pool_max_workers: 12

  # Extended timeouts for large projects
  scan_timeout_seconds: 3600           # 1 hour
  operation_timeout_seconds: 600       # 10 minutes

  # Higher resource thresholds
  memory_warning_threshold_mb: 4096    # 4GB warning
  memory_critical_threshold_mb: 8192   # 8GB critical
  task_count_warning_threshold: 40

  # Larger message limits
  max_message_size_bytes: 52428800     # 50MB
  max_directory_size_mb: 5120          # 5GB
```

### Resource-Constrained Configuration

For systems with limited resources:

```yaml
# .ash/ash.yaml - Resource-constrained setup
mcp-resource-management:
  # Conservative limits
  max_concurrent_scans: 2
  max_concurrent_tasks: 10
  thread_pool_max_workers: 2

  # Shorter timeouts
  scan_timeout_seconds: 1200           # 20 minutes
  operation_timeout_seconds: 180       # 3 minutes

  # Lower resource thresholds
  memory_warning_threshold_mb: 512     # 512MB warning
  memory_critical_threshold_mb: 1024   # 1GB critical
  task_count_warning_threshold: 8

  # Smaller limits
  max_directory_size_mb: 500           # 500MB
```

## Scalability Patterns

### Horizontal Scaling

For organizations with multiple teams or projects:

1. **Multiple MCP Server Instances**
   - Run separate MCP servers for different teams
   - Use different configuration files for different use cases
   - Isolate resource usage per team/project

2. **Load Distribution**
   - Distribute large scans across multiple instances
   - Use different severity thresholds for different environments
   - Implement scan scheduling to avoid peak times

### Vertical Scaling

For single instances handling high load:

1. **Resource Optimization**
   ```yaml
   # Scale up resources
   mcp-resource-management:
     max_concurrent_scans: 10
     thread_pool_max_workers: 16      # Match available CPU cores
     memory_warning_threshold_mb: 8192 # Scale with available RAM
   ```

2. **Performance Tuning**
   - Enable health checks for monitoring
   - Use detailed logging to identify bottlenecks
   - Optimize scanner selection for speed vs coverage

## Performance Monitoring

### Built-in Monitoring

The MCP server provides several monitoring capabilities:

```yaml
# Enable comprehensive monitoring
mcp-resource-management:
  enable_health_checks: true
  enable_resource_logging: true
  log_resource_operations: true        # Enable for troubleshooting only
```

### Monitoring Queries

Ask your AI assistant for performance information:

```
"Show me the current resource usage of the MCP server"
"How many scans are currently running and what's their status?"
"What's the memory usage trend over the last hour?"
"Are there any performance bottlenecks or warnings?"
"Show me the task count and thread pool utilization"
```

### Performance Metrics

The MCP server tracks these key metrics:

- **Active Scan Count**: Number of currently running scans
- **Task Count**: Number of active async tasks
- **Memory Usage**: Current memory consumption
- **Thread Pool Utilization**: Active vs available threads
- **Operation Timings**: Average scan and operation durations
- **Error Rates**: Failed operations and their causes

## Optimization Strategies

### 1. Scanner Selection

Optimize which scanners run based on your needs:

```yaml
# Fast scanning for development
scanners:
  bandit:
    enabled: true      # Fast Python scanner
  detect-secrets:
    enabled: true      # Fast secrets detection
  semgrep:
    enabled: false     # Disable slower scanners for speed
  checkov:
    enabled: false
```

### 2. Directory Optimization

Exclude unnecessary directories to improve performance:

```yaml
global_settings:
  ignore_paths:
    - path: "node_modules/**"
      reason: "Large dependency directory"
    - path: "build/**"
      reason: "Build artifacts"
    - path: "dist/**"
      reason: "Distribution files"
    - path: "*.log"
      reason: "Log files"
    - path: "test_data/**"
      reason: "Test data files"
```

### 3. Severity Filtering

Use appropriate severity thresholds:

```yaml
# Development environment - catch everything
global_settings:
  severity_threshold: "LOW"

# Production environment - focus on critical issues
global_settings:
  severity_threshold: "HIGH"
```

### 4. Concurrent Operation Tuning

Balance concurrency with system resources:

```bash
# Check system resources
nproc                    # Number of CPU cores
free -h                  # Available memory
df -h                    # Disk space

# Configure based on resources
# Rule of thumb: max_concurrent_scans = CPU cores / 2
# thread_pool_max_workers = CPU cores
```

## Performance Benchmarks

### Typical Performance Characteristics

| Project Size | Scan Time | Memory Usage | Recommended Config |
|-------------|-----------|--------------|-------------------|
| Small (< 100 files) | 1-3 minutes | 200-500 MB | Default settings |
| Medium (100-1000 files) | 3-10 minutes | 500 MB - 1 GB | Increase timeouts |
| Large (1000-10000 files) | 10-30 minutes | 1-2 GB | Increase all limits |
| Very Large (> 10000 files) | 30+ minutes | 2+ GB | High-performance config |

### Performance Testing

Test your configuration with representative projects:

```bash
# Test with debug logging
uvx --from=git+https://github.com/awslabs/automated-security-helper@v3.0.0 ash mcp --debug

# Monitor system resources during scans
top -p $(pgrep -f "ash mcp")
```

## Troubleshooting Performance Issues

### Common Performance Problems

1. **Slow Scan Performance**
   - Check concurrent scan limits
   - Verify thread pool size matches CPU cores
   - Review ignored paths configuration
   - Consider scanner selection optimization

2. **High Memory Usage**
   - Reduce concurrent operations
   - Check for memory leaks (should be resolved in v3)
   - Increase memory thresholds if system has capacity
   - Monitor for stuck scans

3. **Resource Exhaustion**
   - Review and adjust resource limits
   - Enable health checks for early warning
   - Implement scan scheduling
   - Consider horizontal scaling

### Performance Debugging

Enable detailed logging for performance analysis:

```yaml
mcp-resource-management:
  enable_resource_logging: true
  log_resource_operations: true
```

This will log:
- Resource allocation and deallocation
- Task creation and completion times
- Memory usage patterns
- Thread pool utilization
- Operation timings

## Best Practices

### 1. Configuration Management

- Start with default settings and adjust based on usage
- Monitor performance metrics regularly
- Document configuration changes and their impact
- Test configuration changes in non-production environments

### 2. Resource Planning

- Plan resource allocation based on expected usage patterns
- Consider peak usage times and concurrent users
- Monitor trends to predict scaling needs
- Implement alerting for resource thresholds

### 3. Operational Excellence

- Implement regular health checks
- Monitor performance metrics over time
- Plan for capacity growth
- Document performance baselines and targets

### 4. Security Considerations

- Balance performance with security coverage
- Don't disable critical scanners for performance
- Consider using different configurations for different environments
- Regularly review and update scanner configurations

## Advanced Configuration

### Custom Resource Limits

For specialized environments:

```yaml
mcp-resource-management:
  # Custom limits based on specific requirements
  max_concurrent_scans: 12             # High-throughput environment
  max_concurrent_tasks: 100            # Complex scanning workflows
  thread_pool_max_workers: 20          # High-core-count systems

  # Extended timeouts for specialized scans
  scan_timeout_seconds: 7200           # 2 hours for very large projects
  operation_timeout_seconds: 1200      # 20 minutes for complex operations

  # Specialized monitoring
  health_check_interval_seconds: 15    # Frequent health checks
  memory_warning_threshold_mb: 16384   # 16GB systems
  memory_critical_threshold_mb: 32768  # 32GB systems
```

### Environment-Specific Configurations

```yaml
# Development environment
mcp-resource-management:
  max_concurrent_scans: 3
  scan_timeout_seconds: 1200           # Shorter timeouts for faster feedback
  enable_resource_logging: true        # Detailed logging for debugging

# Production environment
mcp-resource-management:
  max_concurrent_scans: 8
  scan_timeout_seconds: 3600           # Longer timeouts for completeness
  enable_health_checks: true           # Health monitoring
  enable_resource_logging: false       # Reduce log volume
```

## Related Documentation

- [MCP Tutorial](../tutorials/using-ash-with-mcp.md)
- [Configuration Guide](configuration-guide.md)
- [ASH CLI Reference](cli-reference.md)