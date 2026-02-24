require 'test_helper'

class HomeControllerTest < ActionDispatch::IntegrationTest
  test "should get index" do
    get home_index_url
    assert_response :success
  end

  test "should get one" do
    get home_one_url
    assert_response :success
  end

  test "should get two" do
    get home_two_url
    assert_response :success
  end

end
