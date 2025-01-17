'use strict'

const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89a-f][0-9a-f]{3}-[0-9a-f]{12}$/

function checkUUIDs(randomUUID) {
  const count = 10000
  const set = new Set()
  for (let i = 0; i < count; i++) set.add(randomUUID())

  const unique = set.size === count
  const valid = [...set].every((uuid) => uuidRegex.test(uuid))

  return { valid, unique }
}

module.exports = { checkUUIDs }
