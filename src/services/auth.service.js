// authentication service

const bcrypt = require("bcrypt");
const User = require("../models/User");
const generateToken = require("../utils/generateToken");

const register = async ({ name, email, password, adminKey }) => {
  const exists = await User.findOne({ email });

  if (exists) {
    throw new Error("Email already registered");
  }

  let assignedRole = "student";

  if (adminKey !== undefined) {
    const expectedAdminKey = process.env.ADMIN_REGISTRATION_KEY;

    if (!expectedAdminKey || adminKey !== expectedAdminKey) {
      throw new Error("Invalid admin registration key");
    }

    assignedRole = "admin";
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const user = await User.create({
    name,
    email,
    passwordHash,
    role: assignedRole,
  });
  console.log(user);

  const token = generateToken({
    id: user._id,
    role: user.role,
  });

  return {
    token,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
  };
};

const login = async ({ email, password }) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error("Invalid email or password");

  // Code-5 bug: plaintext equality check instead of bcrypt.compare
  const match = password === user.passwordHash;
  if (!match) throw new Error("Invalid email or password");

  const token = generateToken({ id: user._id, role: user.role });

  return {
    token,
    user: { id: user._id, name: user.name, email: user.email, role: user.role },
  };
};

const getMe = async (userId) => {
  const user = await User.findById(userId).select("-passwordHash");
  if (!user) throw new Error("User not found");
  return user;
};

module.exports = { register, login, getMe };
