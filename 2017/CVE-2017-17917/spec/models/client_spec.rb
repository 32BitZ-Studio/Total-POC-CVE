require 'rails_helper'

RSpec.describe Client, type: :model do
  it "is valid with valid attributes" do
    client = build(:client)
    expect(client).to be_valid
  end

  it "is not valid without a first name" do
    client = build(:client, first_name: nil)
    expect(client).to_not be_valid
    expect(client.errors[:first_name]).to include("can't be blank")
  end

  it "is not valid without a last name" do
    client = build(:client, last_name: nil)
    expect(client).to_not be_valid
    expect(client.errors[:last_name]).to include("can't be blank")
  end

  it "is not valid without a CPF" do
    client = build(:client, cpf: nil)
    expect(client).to_not be_valid
    expect(client.errors[:cpf]).to include("can't be blank")
  end

  it "is not valid without a phone" do
    client = build(:client, phone: nil)
    expect(client).to_not be_valid
    expect(client.errors[:phone]).to include("can't be blank")
  end

  it "is not valid without an email" do
    client = build(:client, email: nil)
    expect(client).to_not be_valid
    expect(client.errors[:email]).to include("can't be blank")
  end
end