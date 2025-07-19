# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resource monitoring and health checks for MCP server resource management.

This module provides comprehensive monitoring capabilities including resource
usage tracking, health checks, alerting thresholds, and monitoring endpoints
for all resource managers in the MCP server implementation.
"""

import asyncio
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from automated_security_helper.utils.log import ASH_LOGGER


class HealthStatus(Enum):
    """Health status enumeration."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AlertLevel(Enum):
    """Alert level enumeration."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class HealthCheckResult:
    """Result of a health check operation."""

    component: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    check_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "component": self.component,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "check_duration_ms": self.check_duration_ms,
        }


@dataclass
class ResourceMetrics:
    """Resource utilization metrics."""

    timestamp: datetime
    memory_usage_mb: float
    cpu_usage_percent: float
    thread_count: int
    active_tasks: int
    active_scans: int
    thread_pool_utilization: float
    event_subscriptions: int
    scan_queue_size: int
    uptime_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_usage_percent": self.cpu_usage_percent,
            "thread_count": self.thread_count,
            "active_tasks": self.active_tasks,
            "active_scans": self.active_scans,
            "thread_pool_utilization": self.thread_pool_utilization,
            "event_subscriptions": self.event_subscriptions,
            "scan_queue_size": self.scan_queue_size,
            "uptime_seconds": self.uptime_seconds,
        }


@dataclass
class AlertThresholds:
    """Configurable alert thresholds for resource monitoring."""

    memory_warning_mb: float = 500.0
    memory_critical_mb: float = 1000.0
    cpu_warning_percent: float = 70.0
    cpu_critical_percent: float = 90.0
    thread_pool_warning_utilization: float = 0.8
    thread_pool_critical_utilization: float = 0.95
    active_tasks_warning: int = 10
    active_tasks_critical: int = 20
    active_scans_warning: int = 5
    active_scans_critical: int = 8
    event_subscriptions_warning: int = 50
    event_subscriptions_critical: int = 100
    scan_queue_warning: int = 5
    scan_queue_critical: int = 10

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for configuration."""
        return {
            "memory_warning_mb": self.memory_warning_mb,
            "memory_critical_mb": self.memory_critical_mb,
            "cpu_warning_percent": self.cpu_warning_percent,
            "cpu_critical_percent": self.cpu_critical_percent,
            "thread_pool_warning_utilization": self.thread_pool_warning_utilization,
            "thread_pool_critical_utilization": self.thread_pool_critical_utilization,
            "active_tasks_warning": self.active_tasks_warning,
            "active_tasks_critical": self.active_tasks_critical,
            "active_scans_warning": self.active_scans_warning,
            "active_scans_critical": self.active_scans_critical,
            "event_subscriptions_warning": self.event_subscriptions_warning,
            "event_subscriptions_critical": self.event_subscriptions_critical,
            "scan_queue_warning": self.scan_queue_warning,
            "scan_queue_critical": self.scan_queue_critical,
        }


@dataclass
class Alert:
    """Alert information."""

    component: str
    level: AlertLevel
    message: str
    metric_name: str
    current_value: Union[int, float]
    threshold_value: Union[int, float]
    timestamp: datetime = field(default_factory=datetime.now)
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "component": self.component,
            "level": self.level.value,
            "message": self.message,
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "threshold_value": self.threshold_value,
            "timestamp": self.timestamp.isoformat(),
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class ResourceMonitor:
    """Comprehensive resource monitoring and health checking system.

    This class provides centralized monitoring capabilities for all resource
    managers, including health checks, metrics collection, alerting, and
    monitoring endpoints for observability.
    """

    def __init__(
        self,
        task_manager=None,
        state_manager=None,
        resource_manager=None,
        event_manager=None,
        alert_thresholds: Optional[AlertThresholds] = None,
        metrics_retention_hours: int = 24,
        health_check_interval_seconds: int = 30,
    ):
        """Initialize the ResourceMonitor.

        Args:
            task_manager: TaskManager instance to monitor
            state_manager: StateManager instance to monitor
            resource_manager: ResourceManager instance to monitor
            event_manager: EventSubscriptionManager instance to monitor
            alert_thresholds: Custom alert thresholds
            metrics_retention_hours: How long to retain metrics history
            health_check_interval_seconds: Interval for automatic health checks
        """
        self._task_manager = task_manager
        self._state_manager = state_manager
        self._resource_manager = resource_manager
        self._event_manager = event_manager

        self._alert_thresholds = alert_thresholds or AlertThresholds()
        self._metrics_retention_hours = metrics_retention_hours
        self._health_check_interval = health_check_interval_seconds

        self._logger = ASH_LOGGER
        self._start_time = time.time()

        # Metrics storage
        self._metrics_history: List[ResourceMetrics] = []
        self._metrics_lock = asyncio.Lock()

        # Health check results
        self._health_results: Dict[str, HealthCheckResult] = {}
        self._health_lock = asyncio.Lock()

        # Alert management
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        self._alert_callbacks: List[Callable[[Alert], None]] = []
        self._alert_lock = asyncio.Lock()

        # Monitoring control
        self._monitoring_enabled = True
        self._monitoring_task: Optional[asyncio.Task] = None

    async def start_monitoring(self) -> None:
        """Start automatic monitoring and health checks."""
        if self._monitoring_task and not self._monitoring_task.done():
            self._logger.warning("Monitoring already started")
            return

        self._monitoring_enabled = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._logger.info(
            f"Started resource monitoring with {self._health_check_interval}s interval"
        )

    async def stop_monitoring(self) -> None:
        """Stop automatic monitoring."""
        self._monitoring_enabled = False

        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

        self._logger.info("Stopped resource monitoring")

    async def _monitoring_loop(self) -> None:
        """Main monitoring loop for periodic health checks and metrics collection."""
        while self._monitoring_enabled:
            try:
                # Collect metrics
                await self._collect_metrics()

                # Perform health checks
                await self._perform_health_checks()

                # Check for alerts
                await self._check_alerts()

                # Clean up old data
                await self._cleanup_old_data()

                # Wait for next interval
                await asyncio.sleep(self._health_check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.error(f"Error in monitoring loop: {str(e)}")
                await asyncio.sleep(min(self._health_check_interval, 10))

    async def _collect_metrics(self) -> None:
        """Collect current resource metrics."""
        try:
            # Get system metrics
            memory_mb, cpu_percent = self._get_system_metrics()
            thread_count = threading.active_count()
            uptime = time.time() - self._start_time

            # Get manager-specific metrics
            active_tasks = (
                self._task_manager.get_task_count() if self._task_manager else 0
            )

            active_scans = 0
            scan_queue_size = 0
            if self._state_manager:
                state_stats = self._state_manager.get_state_statistics()
                active_scans = state_stats.get("active_directory_registrations", 0)
                # Estimate queue size based on status counts
                status_counts = state_stats.get("scan_status_counts", {})
                scan_queue_size = status_counts.get("queued", 0) + status_counts.get(
                    "initializing", 0
                )

            thread_pool_utilization = 0.0
            if self._resource_manager:
                resource_stats = self._resource_manager.get_resource_stats()
                if resource_stats.thread_pool_size > 0:
                    thread_pool_utilization = (
                        resource_stats.thread_pool_active
                        / resource_stats.thread_pool_size
                    )

            event_subscriptions = 0
            if self._event_manager:
                event_stats = self._event_manager.get_subscription_statistics()
                event_subscriptions = event_stats.get("total_subscriptions", 0)

            # Create metrics object
            metrics = ResourceMetrics(
                timestamp=datetime.now(),
                memory_usage_mb=memory_mb,
                cpu_usage_percent=cpu_percent,
                thread_count=thread_count,
                active_tasks=active_tasks,
                active_scans=active_scans,
                thread_pool_utilization=thread_pool_utilization,
                event_subscriptions=event_subscriptions,
                scan_queue_size=scan_queue_size,
                uptime_seconds=uptime,
            )

            # Store metrics
            async with self._metrics_lock:
                self._metrics_history.append(metrics)

                # Log metrics periodically
                if len(self._metrics_history) % 10 == 0:  # Every 10 collections
                    self._logger.debug(f"Resource metrics: {metrics.to_dict()}")

        except Exception as e:
            self._logger.error(f"Error collecting metrics: {str(e)}")

    def _get_system_metrics(self) -> Tuple[float, float]:
        """Get system memory and CPU metrics.

        Returns:
            Tuple of (memory_mb, cpu_percent)
        """
        memory_mb = 0.0
        cpu_percent = 0.0

        try:
            import resource

            memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # On Linux, ru_maxrss is in KB; on macOS, it's in bytes
            if memory_kb > 1024 * 1024:  # Likely bytes (macOS)
                memory_mb = memory_kb / (1024 * 1024)
            else:  # Likely KB (Linux)
                memory_mb = memory_kb / 1024
        except Exception:
            memory_mb = 0.0

        return memory_mb, cpu_percent

    async def _perform_health_checks(self) -> None:
        """Perform health checks on all managed components."""
        health_results = []

        # Check task manager health
        if self._task_manager:
            result = await self._check_task_manager_health()
            health_results.append(result)

        # Check state manager health
        if self._state_manager:
            result = await self._check_state_manager_health()
            health_results.append(result)

        # Check resource manager health
        if self._resource_manager:
            result = await self._check_resource_manager_health()
            health_results.append(result)

        # Check event manager health
        if self._event_manager:
            result = await self._check_event_manager_health()
            health_results.append(result)

        # Store health results
        async with self._health_lock:
            for result in health_results:
                self._health_results[result.component] = result

    async def _check_task_manager_health(self) -> HealthCheckResult:
        """Check task manager health."""
        start_time = time.time()

        try:
            task_count = self._task_manager.get_task_count()

            # Determine health status
            if task_count >= self._alert_thresholds.active_tasks_critical:
                status = HealthStatus.CRITICAL
                message = f"Critical: {task_count} active tasks (threshold: {self._alert_thresholds.active_tasks_critical})"
            elif task_count >= self._alert_thresholds.active_tasks_warning:
                status = HealthStatus.WARNING
                message = f"Warning: {task_count} active tasks (threshold: {self._alert_thresholds.active_tasks_warning})"
            else:
                status = HealthStatus.HEALTHY
                message = f"Healthy: {task_count} active tasks"

            details = {
                "active_tasks": task_count,
                "task_info": self._task_manager.get_all_tasks_info()[
                    :5
                ],  # First 5 tasks
            }

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Health check failed: {str(e)}"
            details = {"error": str(e)}

        duration_ms = (time.time() - start_time) * 1000

        return HealthCheckResult(
            component="task_manager",
            status=status,
            message=message,
            details=details,
            check_duration_ms=duration_ms,
        )

    async def _check_state_manager_health(self) -> HealthCheckResult:
        """Check state manager health."""
        start_time = time.time()

        try:
            # Get state statistics
            stats = self._state_manager.get_state_statistics()

            # Check for consistency issues
            consistency_issues = await self._state_manager.validate_state_consistency()

            # Determine health status
            if consistency_issues:
                status = HealthStatus.CRITICAL
                message = (
                    f"Critical: {len(consistency_issues)} state consistency issues"
                )
            elif (
                stats.get("active_directory_registrations", 0)
                >= self._alert_thresholds.active_scans_critical
            ):
                status = HealthStatus.CRITICAL
                message = (
                    f"Critical: {stats['active_directory_registrations']} active scans"
                )
            elif (
                stats.get("active_directory_registrations", 0)
                >= self._alert_thresholds.active_scans_warning
            ):
                status = HealthStatus.WARNING
                message = (
                    f"Warning: {stats['active_directory_registrations']} active scans"
                )
            else:
                status = HealthStatus.HEALTHY
                message = f"Healthy: {stats.get('total_scans', 0)} total scans, {stats.get('active_directory_registrations', 0)} active"

            details = {"statistics": stats, "consistency_issues": consistency_issues}

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Health check failed: {str(e)}"
            details = {"error": str(e)}

        duration_ms = (time.time() - start_time) * 1000

        return HealthCheckResult(
            component="state_manager",
            status=status,
            message=message,
            details=details,
            check_duration_ms=duration_ms,
        )

    async def _check_resource_manager_health(self) -> HealthCheckResult:
        """Check resource manager health."""
        start_time = time.time()

        try:
            # Get resource statistics
            stats = self._resource_manager.get_resource_stats()
            detailed_status = await self._resource_manager.get_detailed_status()

            # Check thread pool utilization
            thread_utilization = 0.0
            if stats.thread_pool_size > 0:
                thread_utilization = stats.thread_pool_active / stats.thread_pool_size

            # Determine health status
            if (
                thread_utilization
                >= self._alert_thresholds.thread_pool_critical_utilization
            ):
                status = HealthStatus.CRITICAL
                message = f"Critical: Thread pool {thread_utilization:.1%} utilized"
            elif (
                thread_utilization
                >= self._alert_thresholds.thread_pool_warning_utilization
            ):
                status = HealthStatus.WARNING
                message = f"Warning: Thread pool {thread_utilization:.1%} utilized"
            elif not detailed_status["status"]["is_healthy"]:
                status = HealthStatus.WARNING
                message = "Warning: Resource manager reports unhealthy status"
            else:
                status = HealthStatus.HEALTHY
                message = f"Healthy: Thread pool {thread_utilization:.1%} utilized, {stats.active_scans} active scans"

            details = {
                "resource_stats": stats.__dict__
                if hasattr(stats, "__dict__")
                else str(stats),
                "detailed_status": detailed_status,
                "thread_utilization": thread_utilization,
            }

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Health check failed: {str(e)}"
            details = {"error": str(e)}

        duration_ms = (time.time() - start_time) * 1000

        return HealthCheckResult(
            component="resource_manager",
            status=status,
            message=message,
            details=details,
            check_duration_ms=duration_ms,
        )

    async def _check_event_manager_health(self) -> HealthCheckResult:
        """Check event manager health."""
        start_time = time.time()

        try:
            # Get subscription statistics
            stats = self._event_manager.get_subscription_statistics()
            cleanup_errors = self._event_manager.get_cleanup_errors(limit=10)

            total_subscriptions = stats.get("total_subscriptions", 0)

            # Determine health status
            if (
                total_subscriptions
                >= self._alert_thresholds.event_subscriptions_critical
            ):
                status = HealthStatus.CRITICAL
                message = f"Critical: {total_subscriptions} event subscriptions"
            elif (
                total_subscriptions
                >= self._alert_thresholds.event_subscriptions_warning
            ):
                status = HealthStatus.WARNING
                message = f"Warning: {total_subscriptions} event subscriptions"
            elif cleanup_errors:
                status = HealthStatus.WARNING
                message = f"Warning: {len(cleanup_errors)} recent cleanup errors"
            else:
                status = HealthStatus.HEALTHY
                message = f"Healthy: {total_subscriptions} event subscriptions"

            details = {"statistics": stats, "recent_cleanup_errors": cleanup_errors}

        except Exception as e:
            status = HealthStatus.UNKNOWN
            message = f"Health check failed: {str(e)}"
            details = {"error": str(e)}

        duration_ms = (time.time() - start_time) * 1000

        return HealthCheckResult(
            component="event_manager",
            status=status,
            message=message,
            details=details,
            check_duration_ms=duration_ms,
        )

    async def _check_alerts(self) -> None:
        """Check current metrics against alert thresholds."""
        if not self._metrics_history:
            return

        # Get latest metrics
        latest_metrics = self._metrics_history[-1]

        # Check each threshold
        alerts_to_check = [
            (
                "memory_usage",
                latest_metrics.memory_usage_mb,
                self._alert_thresholds.memory_warning_mb,
                self._alert_thresholds.memory_critical_mb,
            ),
            (
                "cpu_usage",
                latest_metrics.cpu_usage_percent,
                self._alert_thresholds.cpu_warning_percent,
                self._alert_thresholds.cpu_critical_percent,
            ),
            (
                "thread_pool_utilization",
                latest_metrics.thread_pool_utilization * 100,
                self._alert_thresholds.thread_pool_warning_utilization * 100,
                self._alert_thresholds.thread_pool_critical_utilization * 100,
            ),
            (
                "active_tasks",
                latest_metrics.active_tasks,
                self._alert_thresholds.active_tasks_warning,
                self._alert_thresholds.active_tasks_critical,
            ),
            (
                "active_scans",
                latest_metrics.active_scans,
                self._alert_thresholds.active_scans_warning,
                self._alert_thresholds.active_scans_critical,
            ),
            (
                "event_subscriptions",
                latest_metrics.event_subscriptions,
                self._alert_thresholds.event_subscriptions_warning,
                self._alert_thresholds.event_subscriptions_critical,
            ),
            (
                "scan_queue_size",
                latest_metrics.scan_queue_size,
                self._alert_thresholds.scan_queue_warning,
                self._alert_thresholds.scan_queue_critical,
            ),
        ]

        async with self._alert_lock:
            for (
                metric_name,
                current_value,
                warning_threshold,
                critical_threshold,
            ) in alerts_to_check:
                alert_key = f"resource_monitor_{metric_name}"

                # Determine alert level
                alert_level = None
                threshold_value = None

                if current_value >= critical_threshold:
                    alert_level = AlertLevel.CRITICAL
                    threshold_value = critical_threshold
                elif current_value >= warning_threshold:
                    alert_level = AlertLevel.WARNING
                    threshold_value = warning_threshold

                # Handle alert
                if alert_level:
                    # Create or update alert
                    if alert_key not in self._active_alerts:
                        alert = Alert(
                            component="resource_monitor",
                            level=alert_level,
                            message=f"{metric_name.replace('_', ' ').title()} {alert_level.value}: {current_value} >= {threshold_value}",
                            metric_name=metric_name,
                            current_value=current_value,
                            threshold_value=threshold_value or 0,
                        )

                        self._active_alerts[alert_key] = alert
                        self._alert_history.append(alert)

                        # Trigger alert callbacks
                        await self._trigger_alert_callbacks(alert)

                        self._logger.warning(f"Alert triggered: {alert.message}")
                    else:
                        # Update existing alert
                        existing_alert = self._active_alerts[alert_key]
                        existing_alert.current_value = current_value
                        existing_alert.level = alert_level
                        existing_alert.threshold_value = threshold_value
                        existing_alert.message = f"{metric_name.replace('_', ' ').title()} {alert_level.value}: {current_value} >= {threshold_value}"

                else:
                    # Resolve alert if it exists
                    if alert_key in self._active_alerts:
                        alert = self._active_alerts[alert_key]
                        alert.resolved = True
                        alert.resolved_at = datetime.now()

                        del self._active_alerts[alert_key]

                        self._logger.info(f"Alert resolved: {alert.message}")

    async def _trigger_alert_callbacks(self, alert: Alert) -> None:
        """Trigger registered alert callbacks."""
        for callback in self._alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                self._logger.error(f"Error in alert callback: {str(e)}")

    async def _cleanup_old_data(self) -> None:
        """Clean up old metrics and alert history."""
        cutoff_time = datetime.now() - timedelta(hours=self._metrics_retention_hours)

        # Clean up metrics
        async with self._metrics_lock:
            self._metrics_history = [
                m for m in self._metrics_history if m.timestamp > cutoff_time
            ]

        # Clean up alert history (keep more alerts for longer)
        alert_cutoff = datetime.now() - timedelta(
            hours=self._metrics_retention_hours * 2
        )
        async with self._alert_lock:
            self._alert_history = [
                a for a in self._alert_history if a.timestamp > alert_cutoff
            ]

    # Public API methods for monitoring endpoints

    async def get_current_metrics(self) -> Optional[Dict[str, Any]]:
        """Get the most recent resource metrics.

        Returns:
            Dictionary with current metrics or None if no metrics available
        """
        async with self._metrics_lock:
            if not self._metrics_history:
                return None
            return self._metrics_history[-1].to_dict()

    async def get_metrics_history(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get metrics history for the specified time period.

        Args:
            hours: Number of hours of history to return

        Returns:
            List of metrics dictionaries
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)

        async with self._metrics_lock:
            return [
                m.to_dict() for m in self._metrics_history if m.timestamp > cutoff_time
            ]

    async def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of all components.

        Returns:
            Dictionary with health status information
        """
        async with self._health_lock:
            overall_status = HealthStatus.HEALTHY

            # Determine overall status
            for result in self._health_results.values():
                if result.status == HealthStatus.CRITICAL:
                    overall_status = HealthStatus.CRITICAL
                    break
                elif (
                    result.status == HealthStatus.WARNING
                    and overall_status == HealthStatus.HEALTHY
                ):
                    overall_status = HealthStatus.WARNING
                elif (
                    result.status == HealthStatus.UNKNOWN
                    and overall_status == HealthStatus.HEALTHY
                ):
                    overall_status = HealthStatus.UNKNOWN

            return {
                "overall_status": overall_status.value,
                "components": {
                    name: result.to_dict()
                    for name, result in self._health_results.items()
                },
                "last_check": max(
                    (result.timestamp for result in self._health_results.values()),
                    default=datetime.now(),
                ).isoformat(),
            }

    async def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts.

        Returns:
            List of active alert dictionaries
        """
        async with self._alert_lock:
            return [alert.to_dict() for alert in self._active_alerts.values()]

    async def get_alert_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get alert history for the specified time period.

        Args:
            hours: Number of hours of history to return

        Returns:
            List of alert dictionaries
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)

        async with self._alert_lock:
            return [
                alert.to_dict()
                for alert in self._alert_history
                if alert.timestamp > cutoff_time
            ]

    def add_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Add a callback to be triggered when alerts are raised.

        Args:
            callback: Function to call when an alert is triggered (can be async)
        """
        self._alert_callbacks.append(callback)

    def remove_alert_callback(self, callback: Callable[[Alert], None]) -> bool:
        """Remove an alert callback.

        Args:
            callback: The callback function to remove

        Returns:
            True if callback was removed, False if not found
        """
        try:
            self._alert_callbacks.remove(callback)
            return True
        except ValueError:
            return False

    async def update_alert_thresholds(self, thresholds: AlertThresholds) -> None:
        """Update alert thresholds.

        Args:
            thresholds: New alert thresholds
        """
        self._alert_thresholds = thresholds
        self._logger.info("Updated alert thresholds")

    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring system status.

        Returns:
            Dictionary with monitoring status information
        """
        return {
            "monitoring_enabled": self._monitoring_enabled,
            "monitoring_active": self._monitoring_task is not None
            and not self._monitoring_task.done(),
            "health_check_interval_seconds": self._health_check_interval,
            "metrics_retention_hours": self._metrics_retention_hours,
            "metrics_count": len(self._metrics_history),
            "active_alerts_count": len(self._active_alerts),
            "alert_history_count": len(self._alert_history),
            "alert_callbacks_count": len(self._alert_callbacks),
            "uptime_seconds": time.time() - self._start_time,
            "alert_thresholds": self._alert_thresholds.to_dict(),
        }

    async def force_health_check(self) -> Dict[str, Any]:
        """Force an immediate health check of all components.

        Returns:
            Dictionary with health check results
        """
        await self._perform_health_checks()
        return await self.get_health_status()

    async def force_metrics_collection(self) -> Dict[str, Any]:
        """Force immediate metrics collection.

        Returns:
            Dictionary with collected metrics
        """
        await self._collect_metrics()
        return await self.get_current_metrics()
