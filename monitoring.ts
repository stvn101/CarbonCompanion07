import { EventEmitter } from 'events';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { auditLogger, SecurityMonitor, UserRole } from './security';

// Security Event Types
export enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  LOGOUT = 'logout',
  PASSWORD_CHANGE = 'password_change',
  ACCOUNT_LOCKED = 'account_locked',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  DATA_ACCESS = 'data_access',
  DATA_EXPORT = 'data_export',
  ADMIN_ACTION = 'admin_action',
  PERMISSION_DENIED = 'permission_denied',
  API_RATE_LIMIT = 'api_rate_limit',
  SECURITY_SCAN = 'security_scan',
  VULNERABILITY_DETECTED = 'vulnerability_detected',
  SYSTEM_BREACH = 'system_breach'
}

// Risk Levels
export enum RiskLevel {
  LOW = 1,
  MEDIUM = 3,
  HIGH = 6,
  CRITICAL = 9
}

// Security Event Interface
export interface SecurityEvent {
  id: string;
  timestamp: Date;
  type: SecurityEventType;
  userId?: string;
  ipAddress: string;
  userAgent: string;
  resource: string;
  details: Record<string, any>;
  riskLevel: RiskLevel;
  resolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
}

// Threat Intelligence Interface
export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'pattern';
  value: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  description: string;
  createdAt: Date;
  expiresAt?: Date;
}

// Security Metrics Interface
export interface SecurityMetrics {
  totalEvents: number;
  criticalEvents: number;
  highRiskEvents: number;
  resolvedEvents: number;
  averageResolutionTime: number;
  topRiskSources: Array<{ source: string; count: number }>;
  eventsByType: Record<SecurityEventType, number>;
  riskTrends: Array<{ date: Date; riskScore: number }>;
}

// Real-time Security Monitor
export class SecurityEventMonitor extends EventEmitter {
  private events: SecurityEvent[] = [];
  private threatIndicators: ThreatIndicator[] = [];
  private alertThresholds: Map<SecurityEventType, number> = new Map();
  private suspiciousIPs: Set<string> = new Set();
  private blockedIPs: Set<string> = new Set();

  constructor() {
    super();
    this.initializeAlertThresholds();
    this.startThreatIntelligenceUpdates();
  }

  private initializeAlertThresholds(): void {
    this.alertThresholds.set(SecurityEventType.LOGIN_FAILURE, 5);
    this.alertThresholds.set(SecurityEventType.PERMISSION_DENIED, 10);
    this.alertThresholds.set(SecurityEventType.API_RATE_LIMIT, 3);
    this.alertThresholds.set(SecurityEventType.SUSPICIOUS_ACTIVITY, 1);
    this.alertThresholds.set(SecurityEventType.VULNERABILITY_DETECTED, 1);
    this.alertThresholds.set(SecurityEventType.SYSTEM_BREACH, 1);
  }

  private startThreatIntelligenceUpdates(): void {
    // Update threat intelligence every hour
    setInterval(() => {
      this.updateThreatIntelligence();
    }, 60 * 60 * 1000);
  }

  private async updateThreatIntelligence(): Promise<void> {
    try {
      // In production, this would fetch from threat intelligence feeds
      console.log('[THREAT INTEL] Updating threat indicators...');
      
      // Remove expired indicators
      const now = new Date();
      this.threatIndicators = this.threatIndicators.filter(
        indicator => !indicator.expiresAt || indicator.expiresAt > now
      );
      
      // Log threat intelligence update
      this.logEvent({
        type: SecurityEventType.SECURITY_SCAN,
        ipAddress: 'system',
        userAgent: 'threat-intelligence-updater',
        resource: 'threat-indicators',
        details: { 
          activeIndicators: this.threatIndicators.length,
          expiredIndicators: this.threatIndicators.length
        },
        riskLevel: RiskLevel.LOW
      });
    } catch (error) {
      console.error('[THREAT INTEL] Failed to update threat intelligence:', error);
    }
  }

  public logEvent(eventData: Omit<SecurityEvent, 'id' | 'timestamp' | 'resolved'>): void {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      resolved: false,
      ...eventData
    };

    this.events.push(event);
    
    // Check against threat indicators
    this.checkThreatIndicators(event);
    
    // Check for suspicious patterns
    this.detectSuspiciousPatterns(event);
    
    // Emit event for real-time processing
    this.emit('securityEvent', event);
    
    // Log to audit system
    auditLogger.log({
      userId: event.userId || 'system',
      action: event.type,
      resource: event.resource,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      success: event.riskLevel <= RiskLevel.MEDIUM,
      details: event.details,
      riskScore: event.riskLevel
    });

    // Check alert thresholds
    this.checkAlertThresholds(event);
    
    // Auto-resolve low-risk events
    if (event.riskLevel === RiskLevel.LOW) {
      this.resolveEvent(event.id, 'system-auto-resolve');
    }
  }

  private checkThreatIndicators(event: SecurityEvent): void {
    const matchingIndicators = this.threatIndicators.filter(indicator => {
      switch (indicator.type) {
        case 'ip':
          return event.ipAddress === indicator.value;
        case 'domain':
          return event.userAgent.includes(indicator.value);
        case 'pattern':
          return new RegExp(indicator.value).test(JSON.stringify(event.details));
        default:
          return false;
      }
    });

    if (matchingIndicators.length > 0) {
      event.riskLevel = RiskLevel.CRITICAL;
      event.details.threatIndicators = matchingIndicators.map(i => i.id);
      
      this.emit('threatDetected', {
        event,
        indicators: matchingIndicators
      });
    }
  }

  private detectSuspiciousPatterns(event: SecurityEvent): void {
    const recentEvents = this.getRecentEvents(event.ipAddress, 15 * 60 * 1000); // 15 minutes
    
    // Multiple failed logins
    if (event.type === SecurityEventType.LOGIN_FAILURE) {
      const failedLogins = recentEvents.filter(e => e.type === SecurityEventType.LOGIN_FAILURE);
      if (failedLogins.length >= 3) {
        this.suspiciousIPs.add(event.ipAddress);
        event.riskLevel = RiskLevel.HIGH;
        event.details.suspiciousPattern = 'multiple_failed_logins';
      }
    }

    // Rapid API calls
    const apiEvents = recentEvents.filter(e => e.resource.startsWith('/api/'));
    if (apiEvents.length > 100) {
      this.suspiciousIPs.add(event.ipAddress);
      event.riskLevel = RiskLevel.HIGH;
      event.details.suspiciousPattern = 'rapid_api_calls';
    }

    // Geographic anomalies (simplified)
    const userEvents = recentEvents.filter(e => e.userId === event.userId);
    if (userEvents.length > 0 && event.userId) {
      // In production, this would use GeoIP lookup
      event.details.geographicCheck = 'performed';
    }

    // Data exfiltration patterns
    if (event.type === SecurityEventType.DATA_EXPORT) {
      const exportEvents = recentEvents.filter(e => e.type === SecurityEventType.DATA_EXPORT);
      if (exportEvents.length >= 5) {
        event.riskLevel = RiskLevel.CRITICAL;
        event.details.suspiciousPattern = 'excessive_data_export';
      }
    }
  }

  private getRecentEvents(ipAddress: string, timeWindow: number): SecurityEvent[] {
    const cutoff = new Date(Date.now() - timeWindow);
    return this.events.filter(event => 
      event.ipAddress === ipAddress && event.timestamp > cutoff
    );
  }

  private checkAlertThresholds(event: SecurityEvent): void {
    const threshold = this.alertThresholds.get(event.type);
    if (!threshold) return;

    const recentSimilarEvents = this.events.filter(e => 
      e.type === event.type && 
      e.timestamp > new Date(Date.now() - 60 * 60 * 1000) // 1 hour
    );

    if (recentSimilarEvents.length >= threshold) {
      this.emit('alertThresholdExceeded', {
        eventType: event.type,
        count: recentSimilarEvents.length,
        threshold,
        events: recentSimilarEvents
      });
    }
  }

  public resolveEvent(eventId: string, resolvedBy: string): boolean {
    const event = this.events.find(e => e.id === eventId);
    if (!event || event.resolved) return false;

    event.resolved = true;
    event.resolvedAt = new Date();
    event.resolvedBy = resolvedBy;

    this.emit('eventResolved', event);
    return true;
  }

  public blockIP(ipAddress: string, reason: string): void {
    this.blockedIPs.add(ipAddress);
    this.logEvent({
      type: SecurityEventType.ADMIN_ACTION,
      ipAddress: 'system',
      userAgent: 'security-monitor',
      resource: 'ip-blocking',
      details: { blockedIP: ipAddress, reason },
      riskLevel: RiskLevel.MEDIUM
    });
  }

  public unblockIP(ipAddress: string, reason: string): void {
    this.blockedIPs.delete(ipAddress);
    this.logEvent({
      type: SecurityEventType.ADMIN_ACTION,
      ipAddress: 'system',
      userAgent: 'security-monitor',
      resource: 'ip-unblocking',
      details: { unblockedIP: ipAddress, reason },
      riskLevel: RiskLevel.LOW
    });
  }

  public isIPBlocked(ipAddress: string): boolean {
    return this.blockedIPs.has(ipAddress);
  }

  public isIPSuspicious(ipAddress: string): boolean {
    return this.suspiciousIPs.has(ipAddress);
  }

  public getSecurityMetrics(timeRange: number = 24 * 60 * 60 * 1000): SecurityMetrics {
    const cutoff = new Date(Date.now() - timeRange);
    const relevantEvents = this.events.filter(e => e.timestamp > cutoff);

    const eventsByType = relevantEvents.reduce((acc, event) => {
      acc[event.type] = (acc[event.type] || 0) + 1;
      return acc;
    }, {} as Record<SecurityEventType, number>);

    const resolvedEvents = relevantEvents.filter(e => e.resolved);
    const resolutionTimes = resolvedEvents
      .filter(e => e.resolvedAt)
      .map(e => e.resolvedAt!.getTime() - e.timestamp.getTime());

    const averageResolutionTime = resolutionTimes.length > 0
      ? resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length
      : 0;

    const ipCounts = relevantEvents.reduce((acc, event) => {
      acc[event.ipAddress] = (acc[event.ipAddress] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const topRiskSources = Object.entries(ipCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([source, count]) => ({ source, count }));

    return {
      totalEvents: relevantEvents.length,
      criticalEvents: relevantEvents.filter(e => e.riskLevel === RiskLevel.CRITICAL).length,
      highRiskEvents: relevantEvents.filter(e => e.riskLevel >= RiskLevel.HIGH).length,
      resolvedEvents: resolvedEvents.length,
      averageResolutionTime,
      topRiskSources,
      eventsByType,
      riskTrends: this.calculateRiskTrends(relevantEvents)
    };
  }

  private calculateRiskTrends(events: SecurityEvent[]): Array<{ date: Date; riskScore: number }> {
    const dailyRisks = new Map<string, number[]>();
    
    events.forEach(event => {
      const dateKey = event.timestamp.toISOString().split('T')[0];
      if (!dailyRisks.has(dateKey)) {
        dailyRisks.set(dateKey, []);
      }
      dailyRisks.get(dateKey)!.push(event.riskLevel);
    });

    return Array.from(dailyRisks.entries()).map(([dateStr, risks]) => ({
      date: new Date(dateStr),
      riskScore: risks.reduce((a, b) => a + b, 0) / risks.length
    }));
  }

  public getEvents(filters?: {
    type?: SecurityEventType;
    riskLevel?: RiskLevel;
    resolved?: boolean;
    userId?: string;
    ipAddress?: string;
    timeRange?: number;
  }): SecurityEvent[] {
    let filteredEvents = [...this.events];

    if (filters) {
      if (filters.type) {
        filteredEvents = filteredEvents.filter(e => e.type === filters.type);
      }
      if (filters.riskLevel) {
        filteredEvents = filteredEvents.filter(e => e.riskLevel >= filters.riskLevel!);
      }
      if (filters.resolved !== undefined) {
        filteredEvents = filteredEvents.filter(e => e.resolved === filters.resolved);
      }
      if (filters.userId) {
        filteredEvents = filteredEvents.filter(e => e.userId === filters.userId);
      }
      if (filters.ipAddress) {
        filteredEvents = filteredEvents.filter(e => e.ipAddress === filters.ipAddress);
      }
      if (filters.timeRange) {
        const cutoff = new Date(Date.now() - filters.timeRange);
        filteredEvents = filteredEvents.filter(e => e.timestamp > cutoff);
      }
    }

    return filteredEvents.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }
}

// Global security monitor instance
export const securityMonitor = new SecurityEventMonitor();

// Security monitoring middleware
export const securityMonitoringMiddleware = (req: Request, res: Response, next: NextFunction) => {
  // Check if IP is blocked
  if (securityMonitor.isIPBlocked(req.ip)) {
    securityMonitor.logEvent({
      type: SecurityEventType.PERMISSION_DENIED,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || '',
      resource: req.path,
      details: { reason: 'blocked_ip' },
      riskLevel: RiskLevel.HIGH
    });
    return res.status(403).json({ error: 'Access denied' });
  }

  // Enhanced monitoring for suspicious IPs
  if (securityMonitor.isIPSuspicious(req.ip)) {
    securityMonitor.logEvent({
      type: SecurityEventType.SUSPICIOUS_ACTIVITY,
      userId: req.user?.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || '',
      resource: req.path,
      details: { 
        method: req.method,
        query: req.query,
        suspicious: true
      },
      riskLevel: RiskLevel.MEDIUM
    });
  }

  // Log all API access
  securityMonitor.logEvent({
    type: SecurityEventType.DATA_ACCESS,
    userId: req.user?.id,
    ipAddress: req.ip,
    userAgent: req.get('User-Agent') || '',
    resource: req.path,
    details: {
      method: req.method,
      query: req.query,
      authenticated: !!req.user
    },
    riskLevel: RiskLevel.LOW
  });

  next();
};

// Automated Response System
export class AutomatedResponseSystem {
  private responseRules: Map<string, (event: SecurityEvent) => void> = new Map();

  constructor() {
    this.initializeResponseRules();
    this.setupEventListeners();
  }

  private initializeResponseRules(): void {
    // Auto-block IPs with multiple critical events
    this.responseRules.set('critical_ip_blocking', (event: SecurityEvent) => {
      if (event.riskLevel === RiskLevel.CRITICAL) {
        const recentCriticalEvents = securityMonitor.getEvents({
          ipAddress: event.ipAddress,
          riskLevel: RiskLevel.CRITICAL,
          timeRange: 60 * 60 * 1000 // 1 hour
        });

        if (recentCriticalEvents.length >= 3) {
          securityMonitor.blockIP(event.ipAddress, 'automated_critical_events');
        }
      }
    });

    // Auto-lock accounts with suspicious activity
    this.responseRules.set('account_locking', (event: SecurityEvent) => {
      if (event.type === SecurityEventType.LOGIN_FAILURE && event.userId) {
        const recentFailures = securityMonitor.getEvents({
          type: SecurityEventType.LOGIN_FAILURE,
          userId: event.userId,
          timeRange: 15 * 60 * 1000 // 15 minutes
        });

        if (recentFailures.length >= 5) {
          // In production, this would lock the user account
          securityMonitor.logEvent({
            type: SecurityEventType.ACCOUNT_LOCKED,
            userId: event.userId,
            ipAddress: event.ipAddress,
            userAgent: event.userAgent,
            resource: 'account-security',
            details: { reason: 'automated_failed_logins', attempts: recentFailures.length },
            riskLevel: RiskLevel.HIGH
          });
        }
      }
    });

    // Rate limiting enforcement
    this.responseRules.set('rate_limiting', (event: SecurityEvent) => {
      if (event.type === SecurityEventType.API_RATE_LIMIT) {
        const recentRateLimits = securityMonitor.getEvents({
          type: SecurityEventType.API_RATE_LIMIT,
          ipAddress: event.ipAddress,
          timeRange: 60 * 60 * 1000 // 1 hour
        });

        if (recentRateLimits.length >= 10) {
          securityMonitor.blockIP(event.ipAddress, 'automated_rate_limiting');
        }
      }
    });
  }

  private setupEventListeners(): void {
    securityMonitor.on('securityEvent', (event: SecurityEvent) => {
      this.responseRules.forEach((rule, name) => {
        try {
          rule(event);
        } catch (error) {
          console.error(`[AUTO RESPONSE] Rule ${name} failed:`, error);
        }
      });
    });

    securityMonitor.on('threatDetected', (data: { event: SecurityEvent; indicators: ThreatIndicator[] }) => {
      // Immediate response to threat detection
      securityMonitor.blockIP(data.event.ipAddress, 'automated_threat_detection');
      
      // Alert security team
      this.sendSecurityAlert({
        type: 'threat_detected',
        severity: 'critical',
        event: data.event,
        indicators: data.indicators
      });
    });

    securityMonitor.on('alertThresholdExceeded', (data: any) => {
      this.sendSecurityAlert({
        type: 'threshold_exceeded',
        severity: 'high',
        data
      });
    });
  }

  private sendSecurityAlert(alert: any): void {
    // In production, this would send alerts via email, SMS, Slack, etc.
    console.warn('[SECURITY ALERT]', JSON.stringify(alert, null, 2));
  }
}

// Initialize automated response system
export const automatedResponseSystem = new AutomatedResponseSystem();

// Security Dashboard Data Provider
export class SecurityDashboard {
  public static getOverviewData(): any {
    const metrics = securityMonitor.getSecurityMetrics();
    const recentEvents = securityMonitor.getEvents({ timeRange: 24 * 60 * 60 * 1000 });
    
    return {
      summary: {
        totalEvents: metrics.totalEvents,
        criticalEvents: metrics.criticalEvents,
        resolvedEvents: metrics.resolvedEvents,
        averageResolutionTime: Math.round(metrics.averageResolutionTime / 1000 / 60) // minutes
      },
      riskTrends: metrics.riskTrends,
      topThreats: metrics.topRiskSources,
      recentCriticalEvents: recentEvents
        .filter(e => e.riskLevel >= RiskLevel.HIGH)
        .slice(0, 10),
      eventDistribution: metrics.eventsByType,
      systemStatus: {
        monitoring: 'active',
        threatIntelligence: 'updated',
        automatedResponse: 'enabled',
        lastUpdate: new Date()
      }
    };
  }

  public static getDetailedReport(timeRange: number = 7 * 24 * 60 * 60 * 1000): any {
    const events = securityMonitor.getEvents({ timeRange });
    const metrics = securityMonitor.getSecurityMetrics(timeRange);
    
    return {
      period: {
        start: new Date(Date.now() - timeRange),
        end: new Date(),
        duration: timeRange
      },
      metrics,
      events: events.slice(0, 100), // Limit for performance
      recommendations: this.generateRecommendations(events, metrics)
    };
  }

  private static generateRecommendations(events: SecurityEvent[], metrics: SecurityMetrics): string[] {
    const recommendations: string[] = [];

    if (metrics.criticalEvents > 0) {
      recommendations.push('Review and address all critical security events immediately');
    }

    if (metrics.averageResolutionTime > 60 * 60 * 1000) { // 1 hour
      recommendations.push('Improve incident response time - current average exceeds 1 hour');
    }

    const failedLogins = events.filter(e => e.type === SecurityEventType.LOGIN_FAILURE);
    if (failedLogins.length > 100) {
      recommendations.push('High number of failed login attempts detected - consider implementing additional authentication measures');
    }

    const suspiciousActivity = events.filter(e => e.type === SecurityEventType.SUSPICIOUS_ACTIVITY);
    if (suspiciousActivity.length > 50) {
      recommendations.push('Elevated suspicious activity detected - review security policies and user training');
    }

    if (recommendations.length === 0) {
      recommendations.push('Security posture is good - continue monitoring and maintain current security measures');
    }

    return recommendations;
  }
}

export default {
  SecurityEventMonitor,
  securityMonitor,
  securityMonitoringMiddleware,
  AutomatedResponseSystem,
  automatedResponseSystem,
  SecurityDashboard,
  SecurityEventType,
  RiskLevel
};

