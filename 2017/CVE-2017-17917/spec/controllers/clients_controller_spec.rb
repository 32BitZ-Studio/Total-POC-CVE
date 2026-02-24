require 'rails_helper'

RSpec.describe ClientsController, type: :controller do
  describe "GET #index" do
    it "returns a success response" do
      get :index
      expect(response).to be_successful
    end

    context "with id_search include SQL injection parameter" do
      it "returns all clients" do
        client = create(:client, id: 1)
        client2 = create(:client, id: 2)
        get :index, params: { id_search: '1 OR id > 1' }

        expect(assigns(:clients)).to eq([client, client2])
      end
    end

    context "with id_search parameter" do
      it "returns clients matching the id_search parameter" do
        client = create(:client, id: 6)
        get :index, params: { id_search: 6 }

        expect(assigns(:clients)).to eq([client])
      end
    end

    context "without id_search parameter" do
      it "returns all clients" do
        clients = create_list(:client, 3)

        get :index

        expect(assigns(:clients)).to eq(clients)
      end
   end
  end
end