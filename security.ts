import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { Request, Response, NextFunction } from 'express';

// Security Configuration
export const SECURITY_CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  JWT_EXPIRES_IN: '15m',
  REFRESH_TOKEN_EXPIRES_IN: '7d',
  BCRYPT_ROUNDS: 12,
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutes
  SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
};

// User Roles and Permissions
export enum UserRole {
  SUPER_ADMIN = 'super_admin',
  ORG_ADMIN = 'org_admin',
  MANAGER = 'manager',
  OPERATOR = 'operator',
  VIEWER = 'viewer'
}

export const PERMISSIONS = {
  [UserRole.SUPER_ADMIN]: ['*'],
  [UserRole.ORG_ADMIN]: ['org:*', 'users:*', 'data:*', 'reports:*'],
  [UserRole.MANAGER]: ['data:read', 'data:write', 'reports:read', 'users:read'],
  [UserRole.OPERATOR]: ['data:read', 'data:write', 'operations:*'],
  [UserRole.VIEWER]: ['data:read', 'reports:read']
};

// Audit Log Interface
export interface AuditLog {
  id: string;
  timestamp: Date;
  userId: string;
  action: string;
  resource: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details: Record<string, any>;
  riskScore: number;
}

// Security Headers Middleware
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Rate Limiting
export const createRateLimit = (windowMs: number, max: number, message: string) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      auditLogger.log({
        userId: req.user?.id || 'anonymous',
        action: 'rate_limit_exceeded',
        resource: req.path,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent') || '',
        success: false,
        details: { limit: max, window: windowMs },
        riskScore: 7
      });
      res.status(429).json({ error: message });
    }
  });
};

// Common Rate Limits
export const rateLimits = {
  general: createRateLimit(15 * 60 * 1000, 100, 'Too many requests'),
  auth: createRateLimit(15 * 60 * 1000, 5, 'Too many authentication attempts'),
  api: createRateLimit(60 * 1000, 60, 'API rate limit exceeded'),
  export: createRateLimit(60 * 60 * 1000, 10, 'Too many export requests')
};

// Input Validation
export class InputValidator {
  static validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  static sanitizeInput(input: string): string {
    return input
      .replace(/[<>]/g, '')
      .trim()
      .substring(0, 1000);
  }

  static validateSQLInput(input: string): boolean {
    const sqlInjectionPattern = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i;
    return !sqlInjectionPattern.test(input);
  }

  static validatePassword(password: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (password.length < 12) {
      errors.push('Password must be at least 12 characters long');
    }
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return { valid: errors.length === 0, errors };
  }
}

// Data Encryption
export class DataEncryption {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly KEY_LENGTH = 32;

  static generateKey(): string {
    return crypto.randomBytes(this.KEY_LENGTH).toString('hex');
  }

  static encrypt(data: string, key: string): { encrypted: string; iv: string; tag: string } {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.ALGORITHM, Buffer.from(key, 'hex'), iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  static decrypt(encryptedData: { encrypted: string; iv: string; tag: string }, key: string): string {
    const decipher = crypto.createDecipher(
      this.ALGORITHM,
      Buffer.from(key, 'hex'),
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

// Password Hashing
export class PasswordManager {
  static async hash(password: string): Promise<string> {
    return bcrypt.hash(password, SECURITY_CONFIG.BCRYPT_ROUNDS);
  }

  static async verify(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}

// JWT Token Management
export class TokenManager {
  static generateAccessToken(payload: any): string {
    return jwt.sign(payload, SECURITY_CONFIG.JWT_SECRET, {
      expiresIn: SECURITY_CONFIG.JWT_EXPIRES_IN,
      issuer: 'carboncompanion.tech',
      audience: 'carboncompanion-users'
    });
  }

  static generateRefreshToken(payload: any): string {
    return jwt.sign(payload, SECURITY_CONFIG.JWT_SECRET, {
      expiresIn: SECURITY_CONFIG.REFRESH_TOKEN_EXPIRES_IN,
      issuer: 'carboncompanion.tech',
      audience: 'carboncompanion-users'
    });
  }

  static verifyToken(token: string): any {
    try {
      return jwt.verify(token, SECURITY_CONFIG.JWT_SECRET);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
}

// Audit Logger
export class AuditLogger {
  private logs: AuditLog[] = [];

  log(logEntry: Omit<AuditLog, 'id' | 'timestamp'>): void {
    const auditLog: AuditLog = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...logEntry
    };

    this.logs.push(auditLog);
    
    // In production, this would write to a secure logging service
    console.log('[AUDIT]', JSON.stringify(auditLog));

    // Alert on high-risk activities
    if (auditLog.riskScore >= 8) {
      this.sendSecurityAlert(auditLog);
    }
  }

  private sendSecurityAlert(log: AuditLog): void {
    // In production, this would send alerts to security team
    console.warn('[SECURITY ALERT]', {
      message: 'High-risk security event detected',
      log
    });
  }

  getLogs(filters?: Partial<AuditLog>): AuditLog[] {
    if (!filters) return this.logs;

    return this.logs.filter(log => {
      return Object.entries(filters).every(([key, value]) => {
        return log[key as keyof AuditLog] === value;
      });
    });
  }
}

export const auditLogger = new AuditLogger();

// Authentication Middleware
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    auditLogger.log({
      userId: 'anonymous',
      action: 'auth_missing_token',
      resource: req.path,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || '',
      success: false,
      details: {},
      riskScore: 5
    });
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = TokenManager.verifyToken(token);
    req.user = decoded;
    
    auditLogger.log({
      userId: decoded.id,
      action: 'auth_success',
      resource: req.path,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || '',
      success: true,
      details: { role: decoded.role },
      riskScore: 1
    });
    
    next();
  } catch (error) {
    auditLogger.log({
      userId: 'anonymous',
      action: 'auth_invalid_token',
      resource: req.path,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent') || '',
      success: false,
      details: { error: error.message },
      riskScore: 6
    });
    
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Authorization Middleware
export const authorize = (requiredPermissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = PERMISSIONS[user.role] || [];
    
    // Super admin has all permissions
    if (userPermissions.includes('*')) {
      return next();
    }

    // Check if user has required permissions
    const hasPermission = requiredPermissions.some(permission => {
      return userPermissions.some(userPerm => {
        if (userPerm.endsWith(':*')) {
          const prefix = userPerm.slice(0, -1);
          return permission.startsWith(prefix);
        }
        return userPerm === permission;
      });
    });

    if (!hasPermission) {
      auditLogger.log({
        userId: user.id,
        action: 'auth_insufficient_permissions',
        resource: req.path,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent') || '',
        success: false,
        details: { 
          required: requiredPermissions, 
          userRole: user.role,
          userPermissions 
        },
        riskScore: 7
      });
      
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

// Security Monitoring
export class SecurityMonitor {
  private static suspiciousActivities: Map<string, number> = new Map();

  static trackSuspiciousActivity(userId: string, activity: string): void {
    const key = `${userId}:${activity}`;
    const count = this.suspiciousActivities.get(key) || 0;
    this.suspiciousActivities.set(key, count + 1);

    // Alert if threshold exceeded
    if (count >= 3) {
      auditLogger.log({
        userId,
        action: 'suspicious_activity_detected',
        resource: activity,
        ipAddress: '',
        userAgent: '',
        success: false,
        details: { activity, count: count + 1 },
        riskScore: 9
      });
    }
  }

  static resetSuspiciousActivity(userId: string): void {
    const keysToDelete = Array.from(this.suspiciousActivities.keys())
      .filter(key => key.startsWith(`${userId}:`));
    
    keysToDelete.forEach(key => this.suspiciousActivities.delete(key));
  }
}

// Data Classification
export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted'
}

// Data Retention Policies
export const RETENTION_POLICIES = {
  AUDIT_LOGS: 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
  USER_DATA: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years after deletion
  OPERATIONAL_DATA: 3 * 365 * 24 * 60 * 60 * 1000, // 3 years
  TEMPORARY_DATA: 30 * 24 * 60 * 60 * 1000 // 30 days
};

export default {
  securityHeaders,
  rateLimits,
  InputValidator,
  DataEncryption,
  PasswordManager,
  TokenManager,
  auditLogger,
  authenticateToken,
  authorize,
  SecurityMonitor,
  UserRole,
  PERMISSIONS,
  DataClassification,
  RETENTION_POLICIES
};

