# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for resource monitoring and health checks.

This module tests the ResourceMonitor class and related monitoring functionality
for the MCP server resource management system.
"""

import asyncio
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from automated_security_helper.core.resource_management.monitoring import (
    ResourceMonitor,
    HealthStatus,
    AlertLevel,
    HealthCheckResult,
    ResourceMetrics,
    AlertThresholds,
    Alert,
)
from automated_security_helper.core.resource_management.task_manager import TaskManager
from automated_security_helper.core.resource_management.state_manager import (
    StateManager,
)
from automated_security_helper.core.resource_management.resource_manager import (
    ResourceManager,
)
from automated_security_helper.core.resource_management.event_manager import (
    EventSubscriptionManager,
)


class TestResourceMonitor:
    """Test cases for ResourceMonitor class."""

    @pytest.fixture
    def mock_managers(self):
        """Create mock resource managers for testing."""
        task_manager = Mock(spec=TaskManager)
        task_manager.get_task_count.return_value = 5
        task_manager.get_all_tasks_info.return_value = []
        task_manager.get_health_status = AsyncMock(
            return_value={"status": "healthy", "active_tasks": 5, "is_healthy": True}
        )

        state_manager = Mock(spec=StateManager)
        state_manager.get_state_statistics.return_value = {
            "total_scans": 10,
            "active_directory_registrations": 2,
            "scan_status_counts": {"running": 2, "completed": 8},
        }
        state_manager.validate_state_consistency = AsyncMock(return_value=[])
        state_manager.get_health_status = AsyncMock(
            return_value={"status": "healthy", "total_scans": 10, "is_healthy": True}
        )

        resource_manager = Mock(spec=ResourceManager)
        resource_stats = Mock()
        resource_stats.thread_pool_size = 4
        resource_stats.thread_pool_active = 2
        resource_stats.active_scans = 2
        resource_manager.get_resource_stats.return_value = resource_stats
        resource_manager.get_detailed_status = AsyncMock(
            return_value={"status": {"is_healthy": True}}
        )
        resource_manager.get_health_status = AsyncMock(
            return_value={"status": "healthy", "is_healthy": True}
        )

        event_manager = Mock(spec=EventSubscriptionManager)
        event_manager.get_subscription_statistics.return_value = {
            "total_subscriptions": 15,
            "cleanup_errors_count": 0,
        }
        event_manager.get_cleanup_errors.return_value = []
        event_manager.get_health_status = AsyncMock(
            return_value={
                "status": "healthy",
                "total_subscriptions": 15,
                "is_healthy": True,
            }
        )

        return {
            "task_manager": task_manager,
            "state_manager": state_manager,
            "resource_manager": resource_manager,
            "event_manager": event_manager,
        }

    @pytest.fixture
    def resource_monitor(self, mock_managers):
        """Create ResourceMonitor instance with mock managers."""
        return ResourceMonitor(
            task_manager=mock_managers["task_manager"],
            state_manager=mock_managers["state_manager"],
            resource_manager=mock_managers["resource_manager"],
            event_manager=mock_managers["event_manager"],
            health_check_interval_seconds=1,  # Fast interval for testing
        )

    @pytest.mark.asyncio
    async def test_resource_monitor_initialization(self, resource_monitor):
        """Test ResourceMonitor initialization."""
        assert resource_monitor._monitoring_enabled is True
        assert resource_monitor._monitoring_task is None
        assert len(resource_monitor._metrics_history) == 0
        assert len(resource_monitor._health_results) == 0
        assert len(resource_monitor._active_alerts) == 0

    @pytest.mark.asyncio
    async def test_collect_metrics(self, resource_monitor):
        """Test metrics collection."""
        with patch.object(
            resource_monitor, "_get_system_metrics", return_value=(100.0, 25.0)
        ):
            await resource_monitor._collect_metrics()

        assert len(resource_monitor._metrics_history) == 1
        metrics = resource_monitor._metrics_history[0]

        assert isinstance(metrics, ResourceMetrics)
        assert metrics.memory_usage_mb == 100.0
        assert metrics.cpu_usage_percent == 25.0
        assert metrics.active_tasks == 5
        assert metrics.active_scans == 2
        assert metrics.event_subscriptions == 15

    @pytest.mark.asyncio
    async def test_health_checks(self, resource_monitor):
        """Test health check execution."""
        await resource_monitor._perform_health_checks()

        assert len(resource_monitor._health_results) == 4  # All 4 managers

        # Check that all components were checked
        components = set(resource_monitor._health_results.keys())
        expected_components = {
            "task_manager",
            "state_manager",
            "resource_manager",
            "event_manager",
        }
        assert components == expected_components

        # Check health check results
        for result in resource_monitor._health_results.values():
            assert isinstance(result, HealthCheckResult)
            assert result.status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_task_manager_health_check(self, resource_monitor, mock_managers):
        """Test task manager specific health check."""
        # Test healthy state
        result = await resource_monitor._check_task_manager_health()
        assert result.component == "task_manager"
        assert result.status == HealthStatus.HEALTHY
        assert "5 active tasks" in result.message

        # Test warning state
        mock_managers["task_manager"].get_task_count.return_value = 15
        result = await resource_monitor._check_task_manager_health()
        assert result.status == HealthStatus.WARNING

        # Test critical state
        mock_managers["task_manager"].get_task_count.return_value = 25
        result = await resource_monitor._check_task_manager_health()
        assert result.status == HealthStatus.CRITICAL

    @pytest.mark.asyncio
    async def test_state_manager_health_check(self, resource_monitor, mock_managers):
        """Test state manager specific health check."""
        # Test healthy state
        result = await resource_monitor._check_state_manager_health()
        assert result.component == "state_manager"
        assert result.status == HealthStatus.HEALTHY

        # Test critical state with consistency issues
        mock_managers["state_manager"].validate_state_consistency = AsyncMock(
            return_value=["Consistency issue 1", "Consistency issue 2"]
        )
        result = await resource_monitor._check_state_manager_health()
        assert result.status == HealthStatus.CRITICAL
        assert "consistency issues" in result.message

    @pytest.mark.asyncio
    async def test_resource_manager_health_check(self, resource_monitor, mock_managers):
        """Test resource manager specific health check."""
        # Test healthy state
        result = await resource_monitor._check_resource_manager_health()
        assert result.component == "resource_manager"
        assert result.status == HealthStatus.HEALTHY

        # Test warning state with high thread utilization
        resource_stats = Mock()
        resource_stats.thread_pool_size = 4
        resource_stats.thread_pool_active = 4  # 100% utilization
        resource_stats.active_scans = 2
        mock_managers[
            "resource_manager"
        ].get_resource_stats.return_value = resource_stats

        result = await resource_monitor._check_resource_manager_health()
        assert result.status == HealthStatus.CRITICAL

    @pytest.mark.asyncio
    async def test_event_manager_health_check(self, resource_monitor, mock_managers):
        """Test event manager specific health check."""
        # Test healthy state
        result = await resource_monitor._check_event_manager_health()
        assert result.component == "event_manager"
        assert result.status == HealthStatus.HEALTHY

        # Test warning state with many subscriptions
        mock_managers["event_manager"].get_subscription_statistics.return_value = {
            "total_subscriptions": 150,  # Above warning threshold
            "cleanup_errors_count": 0,
        }
        result = await resource_monitor._check_event_manager_health()
        assert result.status == HealthStatus.CRITICAL

        # Test warning state with cleanup errors
        mock_managers["event_manager"].get_subscription_statistics.return_value = {
            "total_subscriptions": 15,
            "cleanup_errors_count": 5,
        }
        mock_managers["event_manager"].get_cleanup_errors.return_value = [
            {"error": "test error"}
        ]
        result = await resource_monitor._check_event_manager_health()
        assert result.status == HealthStatus.WARNING

    @pytest.mark.asyncio
    async def test_alert_checking(self, resource_monitor):
        """Test alert threshold checking."""
        # Create metrics that exceed thresholds
        high_memory_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=1200.0,  # Above critical threshold
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(high_memory_metrics)

        await resource_monitor._check_alerts()

        # Should have memory usage alert
        assert len(resource_monitor._active_alerts) > 0

        memory_alert_key = "resource_monitor_memory_usage"
        assert memory_alert_key in resource_monitor._active_alerts

        alert = resource_monitor._active_alerts[memory_alert_key]
        assert alert.level == AlertLevel.CRITICAL
        assert alert.current_value == 1200.0

    @pytest.mark.asyncio
    async def test_alert_resolution(self, resource_monitor):
        """Test alert resolution when metrics return to normal."""
        # First create an alert
        high_memory_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=1200.0,
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(high_memory_metrics)
        await resource_monitor._check_alerts()

        assert len(resource_monitor._active_alerts) > 0

        # Now add normal metrics
        normal_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=100.0,  # Below threshold
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=200.0,
        )

        resource_monitor._metrics_history.append(normal_metrics)
        await resource_monitor._check_alerts()

        # Alert should be resolved
        memory_alert_key = "resource_monitor_memory_usage"
        assert memory_alert_key not in resource_monitor._active_alerts

    @pytest.mark.asyncio
    async def test_alert_callbacks(self, resource_monitor):
        """Test alert callback execution."""
        callback_called = False
        alert_received = None

        def alert_callback(alert: Alert):
            nonlocal callback_called, alert_received
            callback_called = True
            alert_received = alert

        resource_monitor.add_alert_callback(alert_callback)

        # Create metrics that trigger an alert
        high_cpu_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=100.0,
            cpu_usage_percent=95.0,  # Above critical threshold
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(high_cpu_metrics)
        await resource_monitor._check_alerts()

        assert callback_called is True
        assert alert_received is not None
        assert alert_received.level == AlertLevel.CRITICAL
        assert alert_received.metric_name == "cpu_usage"

    @pytest.mark.asyncio
    async def test_monitoring_loop_start_stop(self, resource_monitor):
        """Test starting and stopping the monitoring loop."""
        # Start monitoring
        await resource_monitor.start_monitoring()

        assert resource_monitor._monitoring_enabled is True
        assert resource_monitor._monitoring_task is not None
        assert not resource_monitor._monitoring_task.done()

        # Let it run for a short time
        await asyncio.sleep(0.1)

        # Stop monitoring
        await resource_monitor.stop_monitoring()

        assert resource_monitor._monitoring_enabled is False
        assert resource_monitor._monitoring_task.done()

    @pytest.mark.asyncio
    async def test_get_current_metrics(self, resource_monitor):
        """Test getting current metrics."""
        # No metrics initially
        current = await resource_monitor.get_current_metrics()
        assert current is None

        # Add a metric
        await resource_monitor._collect_metrics()

        current = await resource_monitor.get_current_metrics()
        assert current is not None
        assert "timestamp" in current
        assert "memory_usage_mb" in current

    @pytest.mark.asyncio
    async def test_get_health_status(self, resource_monitor):
        """Test getting overall health status."""
        await resource_monitor._perform_health_checks()

        health_status = await resource_monitor.get_health_status()

        assert "overall_status" in health_status
        assert "components" in health_status
        assert "last_check" in health_status

        assert health_status["overall_status"] == "healthy"
        assert len(health_status["components"]) == 4

    @pytest.mark.asyncio
    async def test_get_active_alerts(self, resource_monitor):
        """Test getting active alerts."""
        # No alerts initially
        alerts = await resource_monitor.get_active_alerts()
        assert len(alerts) == 0

        # Create an alert
        high_memory_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=1200.0,
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(high_memory_metrics)
        await resource_monitor._check_alerts()

        alerts = await resource_monitor.get_active_alerts()
        assert len(alerts) > 0

        alert = alerts[0]
        assert "component" in alert
        assert "level" in alert
        assert "message" in alert

    @pytest.mark.asyncio
    async def test_update_alert_thresholds(self, resource_monitor):
        """Test updating alert thresholds."""
        new_thresholds = AlertThresholds(
            memory_warning_mb=200.0, memory_critical_mb=400.0
        )

        await resource_monitor.update_alert_thresholds(new_thresholds)

        assert resource_monitor._alert_thresholds.memory_warning_mb == 200.0
        assert resource_monitor._alert_thresholds.memory_critical_mb == 400.0

    @pytest.mark.asyncio
    async def test_force_health_check(self, resource_monitor):
        """Test forcing immediate health check."""
        result = await resource_monitor.force_health_check()

        assert "overall_status" in result
        assert "components" in result
        assert len(result["components"]) == 4

    @pytest.mark.asyncio
    async def test_force_metrics_collection(self, resource_monitor):
        """Test forcing immediate metrics collection."""
        with patch.object(
            resource_monitor, "_get_system_metrics", return_value=(150.0, 30.0)
        ):
            result = await resource_monitor.force_metrics_collection()

        assert result is not None
        assert result["memory_usage_mb"] == 150.0
        assert result["cpu_usage_percent"] == 30.0

    @pytest.mark.asyncio
    async def test_cleanup_old_data(self, resource_monitor):
        """Test cleanup of old metrics and alerts."""
        # Add old metrics
        old_time = datetime.now() - timedelta(hours=25)  # Older than retention
        old_metrics = ResourceMetrics(
            timestamp=old_time,
            memory_usage_mb=100.0,
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(old_metrics)

        # Add old alert (needs to be older than 2x metrics retention)
        very_old_time = datetime.now() - timedelta(hours=50)  # Older than 2x retention
        old_alert = Alert(
            component="test",
            level=AlertLevel.WARNING,
            message="test alert",
            metric_name="test_metric",
            current_value=100,
            threshold_value=50,
            timestamp=very_old_time,
        )

        resource_monitor._alert_history.append(old_alert)

        # Add recent data
        await resource_monitor._collect_metrics()

        # Cleanup should remove old data but keep recent
        await resource_monitor._cleanup_old_data()

        assert len(resource_monitor._metrics_history) == 1  # Only recent metrics
        assert len(resource_monitor._alert_history) == 0  # Old alert removed

    def test_alert_thresholds_to_dict(self):
        """Test AlertThresholds to_dict conversion."""
        thresholds = AlertThresholds(memory_warning_mb=500.0, cpu_critical_percent=95.0)

        result = thresholds.to_dict()

        assert isinstance(result, dict)
        assert result["memory_warning_mb"] == 500.0
        assert result["cpu_critical_percent"] == 95.0

    def test_health_check_result_to_dict(self):
        """Test HealthCheckResult to_dict conversion."""
        result = HealthCheckResult(
            component="test_component",
            status=HealthStatus.HEALTHY,
            message="All good",
            details={"key": "value"},
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["component"] == "test_component"
        assert result_dict["status"] == "healthy"
        assert result_dict["message"] == "All good"
        assert result_dict["details"] == {"key": "value"}

    def test_resource_metrics_to_dict(self):
        """Test ResourceMetrics to_dict conversion."""
        metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=100.0,
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        result = metrics.to_dict()

        assert isinstance(result, dict)
        assert result["memory_usage_mb"] == 100.0
        assert result["cpu_usage_percent"] == 50.0
        assert "timestamp" in result

    def test_alert_to_dict(self):
        """Test Alert to_dict conversion."""
        alert = Alert(
            component="test_component",
            level=AlertLevel.CRITICAL,
            message="Critical alert",
            metric_name="memory_usage",
            current_value=1000,
            threshold_value=500,
        )

        result = alert.to_dict()

        assert isinstance(result, dict)
        assert result["component"] == "test_component"
        assert result["level"] == "critical"
        assert result["message"] == "Critical alert"
        assert result["current_value"] == 1000

    @pytest.mark.asyncio
    async def test_get_monitoring_status(self, resource_monitor):
        """Test getting monitoring system status."""
        status = await resource_monitor.get_monitoring_status()

        assert isinstance(status, dict)
        assert "monitoring_enabled" in status
        assert "health_check_interval_seconds" in status
        assert "metrics_retention_hours" in status
        assert "alert_thresholds" in status

        assert status["monitoring_enabled"] is True
        assert status["health_check_interval_seconds"] == 1

    @pytest.mark.asyncio
    async def test_system_metrics_without_psutil(self, resource_monitor):
        """Test system metrics collection without psutil."""
        with patch("builtins.__import__") as mock_import:

            def import_side_effect(name, *args, **kwargs):
                if name == "psutil":
                    raise ImportError("No module named 'psutil'")
                return __import__(name, *args, **kwargs)

            mock_import.side_effect = import_side_effect

            memory_mb, cpu_percent = resource_monitor._get_system_metrics()

            # Should return 0 or positive values when psutil is not available
            assert memory_mb >= 0.0
            assert cpu_percent >= 0.0

    @pytest.mark.asyncio
    async def test_async_alert_callback(self, resource_monitor):
        """Test async alert callback execution."""
        callback_called = False

        async def async_alert_callback(alert: Alert):
            nonlocal callback_called
            callback_called = True
            await asyncio.sleep(0.01)  # Simulate async work

        resource_monitor.add_alert_callback(async_alert_callback)

        # Create metrics that trigger an alert
        high_memory_metrics = ResourceMetrics(
            timestamp=datetime.now(),
            memory_usage_mb=1200.0,
            cpu_usage_percent=50.0,
            thread_count=10,
            active_tasks=5,
            active_scans=2,
            thread_pool_utilization=0.5,
            event_subscriptions=15,
            scan_queue_size=1,
            uptime_seconds=100.0,
        )

        resource_monitor._metrics_history.append(high_memory_metrics)
        await resource_monitor._check_alerts()

        assert callback_called is True

    @pytest.mark.asyncio
    async def test_remove_alert_callback(self, resource_monitor):
        """Test removing alert callbacks."""

        def test_callback(alert: Alert):
            pass

        # Add callback
        resource_monitor.add_alert_callback(test_callback)
        assert len(resource_monitor._alert_callbacks) == 1

        # Remove callback
        success = resource_monitor.remove_alert_callback(test_callback)
        assert success is True
        assert len(resource_monitor._alert_callbacks) == 0

        # Try to remove non-existent callback
        success = resource_monitor.remove_alert_callback(test_callback)
        assert success is False

    @pytest.mark.asyncio
    async def test_get_metrics_history(self, resource_monitor):
        """Test getting metrics history for a time period."""
        # Add some metrics
        await resource_monitor._collect_metrics()
        await asyncio.sleep(0.01)
        await resource_monitor._collect_metrics()

        # Get 1 hour of history
        history = await resource_monitor.get_metrics_history(hours=1)

        assert len(history) == 2
        assert all("timestamp" in metric for metric in history)

    @pytest.mark.asyncio
    async def test_get_alert_history(self, resource_monitor):
        """Test getting alert history for a time period."""
        # Create an alert
        alert = Alert(
            component="test",
            level=AlertLevel.WARNING,
            message="test alert",
            metric_name="test_metric",
            current_value=100,
            threshold_value=50,
        )

        resource_monitor._alert_history.append(alert)

        # Get 24 hours of history
        history = await resource_monitor.get_alert_history(hours=24)

        assert len(history) == 1
        assert history[0]["message"] == "test alert"
