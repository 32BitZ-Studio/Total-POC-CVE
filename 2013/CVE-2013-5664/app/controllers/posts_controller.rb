class PostsController < ApplicationController
  def index
    render :text => Post.find_by_name(params[:id]).inspect + "\n"
  end
end
