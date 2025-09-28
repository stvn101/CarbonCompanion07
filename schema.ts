import { pgTable, text, serial, integer, decimal, timestamp, boolean, varchar } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  name: text("name").notNull(),
  replitUserId: text("replit_user_id").unique(),
  role: text("role").notNull().default("user"), // 'admin', 'manager', 'user'
  subscriptionTier: text("subscription_tier").notNull().default("free"), // 'free', 'professional', 'enterprise'
  organizationId: integer("organization_id"),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  lastLoginAt: timestamp("last_login_at"),
});

export const organizations = pgTable("organizations", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  subscriptionTier: text("subscription_tier").notNull().default("professional"), // 'professional', 'enterprise'
  maxUsers: integer("max_users").notNull().default(10),
  adminEmail: text("admin_email").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const userSessions = pgTable("user_sessions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull(),
  sessionToken: text("session_token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const equipment = pgTable("equipment", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  type: text("type").notNull(), // 'truck', 'excavator', 'dozer', 'loader'
  makeModel: text("make_model").notNull(),
  equipmentId: text("equipment_id").notNull().unique(),
  fuelEfficiency: decimal("fuel_efficiency", { precision: 5, scale: 2 }).notNull(), // L/100km for trucks, L/h for machinery
  isActive: boolean("is_active").notNull().default(true),
});

export const projects = pgTable("projects", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  isActive: boolean("is_active").notNull().default(true),
});

export const operations = pgTable("operations", {
  id: serial("id").primaryKey(),
  equipmentId: integer("equipment_id").notNull(),
  projectId: integer("project_id"),
  operationType: text("operation_type").notNull(), // 'delivery', 'earthmoving', 'site-prep', etc.
  operationCategory: text("operation_category").notNull(), // 'material-delivery', 'equipment-transport', etc.
  distance: decimal("distance", { precision: 8, scale: 2 }), // km for delivery trips
  duration: decimal("duration", { precision: 8, scale: 2 }).notNull(), // hours
  fuelUsed: decimal("fuel_used", { precision: 8, scale: 2 }).notNull(), // liters
  loadWeight: decimal("load_weight", { precision: 8, scale: 2 }), // tons
  materialMoved: decimal("material_moved", { precision: 8, scale: 2 }), // m³ for machinery
  notes: text("notes"),
  startTime: timestamp("start_time").notNull().defaultNow(),
  endTime: timestamp("end_time"),
  isCompleted: boolean("is_completed").notNull().default(true),
});

export const insertEquipmentSchema = createInsertSchema(equipment).omit({
  id: true,
  isActive: true,
});

export const insertProjectSchema = createInsertSchema(projects).omit({
  id: true,
  isActive: true,
});

export const insertOperationSchema = createInsertSchema(operations).omit({
  id: true,
  startTime: true,
  endTime: true,
  isCompleted: true,
}).extend({
  distance: z.coerce.number().min(0).optional(),
  duration: z.coerce.number().min(0.1),
  fuelUsed: z.coerce.number().min(0.1),
  loadWeight: z.coerce.number().min(0).optional(),
  materialMoved: z.coerce.number().min(0).optional(),
});

export const startOperationSchema = createInsertSchema(operations).omit({
  id: true,
  startTime: true,
  endTime: true,
  isCompleted: true,
  duration: true,
  fuelUsed: true,
  distance: true,
  loadWeight: true,
  materialMoved: true,
  notes: true,
}).extend({
  notes: z.string().optional(),
});

export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  lastLoginAt: true,
});

export const insertOrganizationSchema = createInsertSchema(organizations).omit({
  id: true,
  createdAt: true,
});

export type Equipment = typeof equipment.$inferSelect;
export type InsertEquipment = z.infer<typeof insertEquipmentSchema>;

export type Project = typeof projects.$inferSelect;
export type InsertProject = z.infer<typeof insertProjectSchema>;

export type Operation = typeof operations.$inferSelect;
export type InsertOperation = z.infer<typeof insertOperationSchema>;

export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;

export type UserSession = typeof userSessions.$inferSelect;

export type OperationWithDetails = Operation & {
  equipment: Equipment;
  project?: Project;
};

export type UserWithOrganization = User & {
  organization?: Organization;
};
