// src/utils/bcryptHelper.js
import bcrypt from 'bcryptjs'

const SALT_ROUNDS = 10

export function hashPasswordSync(plain) {
  const salt = bcrypt.genSaltSync(SALT_ROUNDS)
  return bcrypt.hashSync(String(plain), salt)
}

export function verifyPasswordSync(plain, hash) {
  try {
    return bcrypt.compareSync(String(plain), String(hash))
  } catch (e) {
    console.error('verifyPasswordSync error', e)
    return false
  }
}
